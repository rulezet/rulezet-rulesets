rule Trojan_Autorun_Dump_Generic_Dacic_19E38D3B_A_AAF775A0_203_2 {
  meta:
    description = "datamaliciousorder - file Trojan.Autorun_Dump.Generic.Dacic.19E38D3B.A.AAF775A0_203_2.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "5f5fe1deee0339ff0951ce809e8354958780631086c1743772fe6486efcf1b85"

  strings:
    $s1 = "SOFTWARE\\Microsoft\\NET Framework Setup\\NDP\\v4" fullword wide

  condition:
    uint16(0) == 0x5a4d and
    all of them
}