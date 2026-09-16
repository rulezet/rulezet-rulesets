rule Trojan_Autorun_Dump_Generic_Dacic_19E38D3B_A_AAF775A0_208_2 {
  meta:
    description = "datamaliciousorder - file Trojan.Autorun_Dump.Generic.Dacic.19E38D3B.A.AAF775A0_208_2.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "c85da5228d681603c78ae24ac58f26c7eeb812eca581cc955db4de51d8442661"

  strings:
    $s1 = "#PASSWORD" fullword wide
    $s2 = "J[LiSP" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}