rule Trojan_Autorun_Dump_Generic_Dacic_19E38D3B_A_AAF775A0_23_2 {
  meta:
    description = "datamaliciousorder - file Trojan.Autorun_Dump.Generic.Dacic.19E38D3B.A.AAF775A0_23_2.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "a97ac97f4baf1525bd1a9a38aebd9a7ed0a387660201ee1483f589449481dc43"

  strings:
    $s1 = "/N$Srq?noWT" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}