rule webshell_php_obfuscated_encoding__converted_for_hunting: WEBSHELL HUNT_CONVERTED {
  meta:
    key   = "PHP webshell obfuscated by encoding"
    key   = "https://creativecommons.org/licenses/by-nc/4.0/"
    key   = "Arnim Rupp"
    key   = "2021/04/18"
    score = 40

  strings:
    $enc_eval1   = /(e|\\x65|\\101)(\\x76|\\118)(a|\\x61|\\97)(l|\\x6c|\\108)(\(|\\x28|\\40)/ wide ascii nocase
    $enc_eval2   = /(\\x65|\\101)(v|\\x76|\\118)(a|\\x61|\\97)(l|\\x6c|\\108)(\(|\\x28|\\40)/ wide ascii nocase
    $enc_assert1 = /(a|\\97|\\x61)(\\115|\\x73)(s|\\115|\\x73)(e|\\101|\\x65)(r|\\114|\\x72)(t|\\116|\\x74)(\(|\\x28|\\40)/ wide ascii nocase
    $enc_assert2 = /(\\97|\\x61)(s|\\115|\\x73)(s|\\115|\\x73)(e|\\101|\\x65)(r|\\114|\\x72)(t|\\116|\\x74)(\(|\\x28|\\40)/ wide ascii nocase
    $php_short   = "<?" wide ascii
    $no_xml1     = "<?xml version" nocase wide ascii
    $no_xml2     = "<?xml-stylesheet" nocase wide ascii
    $no_asp1     = "<%@LANGUAGE" nocase wide ascii
    $no_asp2     = /<script language="(vb|jscript|c#)/ nocase wide ascii
    $no_pdf      = "<?xpacket"
    $php_new1    = /<\?=[^?]/ wide ascii
    $php_new2    = "<?php" nocase wide ascii
    $php_new3    = "<script language=\"php" nocase wide ascii

  condition:
    (filesize >= 700KB and filesize < 2100KB
    )
    and
    ((($php_short in (0..100) or $php_short in (filesize - 1000..filesize)) and not any of ($no_*)) or any of ($php_new*)) and any of ($enc*)
}