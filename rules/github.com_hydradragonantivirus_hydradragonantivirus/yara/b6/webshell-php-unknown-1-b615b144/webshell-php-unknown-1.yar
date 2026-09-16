rule webshell_php_unknown_1: WEBSHELL PROD {
  meta:
    description = "obfuscated php webshell"
    license     = "https://creativecommons.org/licenses/by-nc/4.0/"
    author      = "Arnim Rupp"
    hash        = "12ce6c7167b33cc4e8bdec29fb1cfc44ac9487d1"
    hash        = "cf4abbd568ce0c0dfce1f2e4af669ad2"
    date        = "2021/01/07"

  strings:
    $sp0 = /^<\?php \$[a-z]{3,30} = '/ wide ascii
    $sp1 = "=explode(chr(" wide ascii
    $sp2 = "; if (!function_exists('" wide ascii
    $sp3 = " = NULL; for(" wide ascii

  condition:
    filesize < 300KB and
    all of ($sp*)
}