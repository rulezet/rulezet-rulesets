rule webshell_php_unknown_1__converted_for_hunting: WEBSHELL HUNT_CONVERTED {
  meta:
    key   = "obfuscated php webshell"
    key   = "https://creativecommons.org/licenses/by-nc/4.0/"
    key   = "Arnim Rupp"
    key   = "2021/01/07"
    score = 40

  strings:
    $sp0 = /^<\?php \$[a-z]{3,30} = '/ wide ascii
    $sp1 = "=explode(chr(" wide ascii
    $sp2 = "; if (!function_exists('" wide ascii
    $sp3 = " = NULL; for(" wide ascii

  condition:
    (filesize >= 300KB and filesize < 900KB
    )
    and all of ($sp*)
}