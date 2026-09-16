rule webshell_php_obfuscated_fopo__converted_for_hunting: WEBSHELL HUNT_CONVERTED {
  meta:
    key   = "PHP webshell which eval()s obfuscated string"
    key   = "https://creativecommons.org/licenses/by-nc/4.0/"
    key   = "Arnim Rupp"
    key   = "2021/01/12"
    score = 40

  strings:
    $payload   = /(\beval[\t ]*\([^)]|\bassert[\t ]*\([^)])/ nocase wide ascii
    $one1      = "7QGV2YWwo" wide ascii
    $one2      = "tAZXZhbC" wide ascii
    $one3      = "O0BldmFsK" wide ascii
    $one4      = "sAQABlAHYAYQBsACgA" wide ascii
    $one5      = "7AEAAZQB2AGEAbAAoA" wide ascii
    $one6      = "OwBAAGUAdgBhAGwAKA" wide ascii
    $two1      = "7QGFzc2VydC" wide ascii
    $two2      = "tAYXNzZXJ0K" wide ascii
    $two3      = "O0Bhc3NlcnQo" wide ascii
    $two4      = "sAQABhAHMAcwBlAHIAdAAoA" wide ascii
    $two5      = "7AEAAYQBzAHMAZQByAHQAKA" wide ascii
    $two6      = "OwBAAGEAcwBzAGUAcgB0ACgA" wide ascii
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
    (filesize >= 3000KB and filesize < 9000KB
    )
    and
    ((($php_short in (0..100) or $php_short in (filesize - 1000..filesize)) and not any of ($no_*)) or any of ($php_new*)) and $payload and
    (any of ($one*) or any of ($two*))
}