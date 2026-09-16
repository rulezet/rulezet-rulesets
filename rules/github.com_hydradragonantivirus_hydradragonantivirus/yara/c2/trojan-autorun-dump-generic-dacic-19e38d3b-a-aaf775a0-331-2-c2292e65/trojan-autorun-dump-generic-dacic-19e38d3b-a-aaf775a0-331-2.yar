rule Trojan_Autorun_Dump_Generic_Dacic_19E38D3B_A_AAF775A0_331_2 {
  meta:
    description = "datamaliciousorder - file Trojan.Autorun_Dump.Generic.Dacic.19E38D3B.A.AAF775A0_331_2.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "fe9c07268700093813ccf0e6618b6956f5cebffcf4e1447a98fed71c50a3932d"

  strings:
    $s1 = "dFar moz hugi gorodihefuwey baxotegufuz disefa minogadayacob wusidovajihato noviborix giperaceceranuz@Lihalutafe tice hitex camu" wide

  condition:
    uint16(0) == 0x5a4d and
    all of them
}