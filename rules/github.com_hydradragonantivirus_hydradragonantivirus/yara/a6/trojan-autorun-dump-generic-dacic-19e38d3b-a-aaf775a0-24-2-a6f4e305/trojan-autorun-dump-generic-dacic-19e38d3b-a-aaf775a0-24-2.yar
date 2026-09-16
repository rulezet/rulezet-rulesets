rule Trojan_Autorun_Dump_Generic_Dacic_19E38D3B_A_AAF775A0_24_2 {
  meta:
    description = "datamaliciousorder - file Trojan.Autorun_Dump.Generic.Dacic.19E38D3B.A.AAF775A0_24_2.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "4e11e52de70274d137ea7d2e30755fce5f8139daa40ad7fbc0c7d0434926a65b"

  strings:
    $s1 = "BURn%Q" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}