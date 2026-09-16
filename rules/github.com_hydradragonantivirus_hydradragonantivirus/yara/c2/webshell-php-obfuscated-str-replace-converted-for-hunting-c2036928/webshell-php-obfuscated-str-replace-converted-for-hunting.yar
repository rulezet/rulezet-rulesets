rule webshell_php_obfuscated_str_replace__converted_for_hunting: WEBSHELL HUNT_CONVERTED {
  meta:
    key   = "PHP webshell which eval()s obfuscated string"
    key   = "https://creativecommons.org/licenses/by-nc/4.0/"
    key   = "Arnim Rupp"
    key   = "2021/01/12"
    score = 40

  strings:
    $payload1  = "str_replace" fullword wide ascii
    $payload2  = "function" fullword wide ascii
    $goto      = "goto" fullword wide ascii
    $chr1      = "\\61" wide ascii
    $chr2      = "\\112" wide ascii
    $chr3      = "\\120" wide ascii
    $php_short = "<?" wide ascii
    $no_xml1   = "<?xml version" nocase wide ascii
    $no_xml2   = "<?xml-stylesheet" nocase wide ascii
    $no_asp1   = "<%@LANGUAGE" nocase wide ascii
    $no_asp2   = /<script language="(vb|jscript|c#)/ nocase wide ascii
    $no_pdf    = "<?xpacket"
    $php_new1  = /<\?=[^?]/ wide ascii
    $php_new2  = "<?php" nocase wide ascii
    $php_new3  = "<script language=\"php" nocase wide ascii

  condition:
    (filesize >= 300KB and filesize < 900KB
    )
    and
    ((($php_short in (0..100) or $php_short in (filesize - 1000..filesize)) and not any of ($no_*)) or any of ($php_new*)) and any of ($payload*) and #goto > 1 and
    (#chr1 > 10 or #chr2 > 10 or #chr3 > 10)
}