rule Trojan_Autorun_Dump_Generic_Dacic_19E38D3B_A_AAF775A0_687_1 {
  meta:
    description = "datamaliciousorder - file Trojan.Autorun_Dump.Generic.Dacic.19E38D3B.A.AAF775A0_687_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "a87ef9c1d570cbf37b57c0ce06327d0a451c0026757834ad1a013210e9e751d5"

  strings:
    $s1 = "If you want to find out more about academic soft" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}