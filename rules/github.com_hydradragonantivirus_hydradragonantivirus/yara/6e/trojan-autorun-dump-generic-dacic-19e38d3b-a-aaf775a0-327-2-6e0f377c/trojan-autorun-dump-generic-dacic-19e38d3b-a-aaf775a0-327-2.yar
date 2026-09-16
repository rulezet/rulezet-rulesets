rule Trojan_Autorun_Dump_Generic_Dacic_19E38D3B_A_AAF775A0_327_2 {
  meta:
    description = "datamaliciousorder - file Trojan.Autorun_Dump.Generic.Dacic.19E38D3B.A.AAF775A0_327_2.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "95a4427993e79d1dccfbf8b020cb6cd167ba95230f9b1e48977e96bc325d0beb"

  strings:
    $s1 = "PONE',+F" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}