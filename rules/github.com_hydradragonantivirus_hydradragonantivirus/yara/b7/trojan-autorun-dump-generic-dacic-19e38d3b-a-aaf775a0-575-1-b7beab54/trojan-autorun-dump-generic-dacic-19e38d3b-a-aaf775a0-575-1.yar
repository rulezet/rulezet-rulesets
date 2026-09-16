rule Trojan_Autorun_Dump_Generic_Dacic_19E38D3B_A_AAF775A0_575_1 {
  meta:
    description = "datamaliciousorder - file Trojan.Autorun_Dump.Generic.Dacic.19E38D3B.A.AAF775A0_575_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "ef5c27f8a0ab30251f76b4c822a4601dcdba26821e55edc0aaffe3091f2d03bc"

  strings:
    $s1 = ";sOUR LICE" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}