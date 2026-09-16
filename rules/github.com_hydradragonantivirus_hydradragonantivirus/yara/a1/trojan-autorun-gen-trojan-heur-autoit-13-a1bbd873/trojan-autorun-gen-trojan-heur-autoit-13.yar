rule Trojan_Autorun_Gen_Trojan_Heur_AutoIT_13 {
  meta:
    description = "datamaliciousorder - file Trojan.Autorun_Gen.Trojan.Heur.AutoIT.13.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "2f5405e375ab1b358882068b957e8cf2f7caeb847df3e2160a6cdde89d76170d"

  strings:
    $s1  = "    <!-- title and precision sec logo -->" fullword ascii
    $s2  = "<!-- Button returns to sample info page if md5 ok -->" fullword ascii
    $s3  = "    <!-- Mobile friendliness -->" fullword ascii
    $s4  = "    <!-- Favicons/etc. for for various contexts -->" fullword ascii
    $s5  = "    <!-- Bootstrap -->" fullword ascii
    $s6  = "SCRIPT(" fullword wide
    $s7  = "    <script src=\"js/bootstrap.min.js\"></script>" fullword ascii
    $s8  = "    <meta name=\"application-name\" content=\"precisionsec - Custom Threat Intelligence Solutions\">" fullword ascii
    $s9  = "<!--All html into catch block so that nothing is loaded unecessarily-->" fullword ascii
    $s10 = "    <meta name=\"apple-mobile-web-app-title\" content=\"precisionsec\">" fullword ascii
    $s11 = "    <meta name=\"theme-color\" content=\"#ffffff\">" fullword ascii
    $s12 = "    <meta name=\"viewport\" content=\"width=device-width, initial-scale=1, shrink-to-fit=yes\">" fullword ascii
    $s13 = "    <link rel=\"icon\" type=\"image/png\" sizes=\"16x16\" href=\"images/favicon-16x16.png\">" fullword ascii
    $s14 = "    <link rel=\"apple-touch-icon\" sizes=\"72x72\" href=\"images/apple-touch-icon.png\">" fullword ascii
    $s15 = "    <link href=\"css/bootstrap.min.css\" rel=\"stylesheet\">" fullword ascii
    $s16 = "    <link rel=\"icon\" type=\"image/png\" sizes=\"32x32\" href=\"images/favicon-32x32.png\">" fullword ascii
    $s17 = "    <link rel=\"mask-icon\" href=\"images/safari-pinned-tab.svg\" color=\"#5bbad5\">" fullword ascii
    $s18 = "    <div class=\"text-left\" style=\"margin-bottom: 30px\">That sample is not currently available for download.</div>" fullword ascii
    $s19 = "zy?kETo" fullword ascii
    $s20 = "    <meta name=\"msapplication-TileColor\" content=\"#2d89ef\">" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    8 of them
}