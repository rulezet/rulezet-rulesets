rule Trojan_Autorun_Dump_Generic_Dacic_BC58E3CC_A_00D7D229_480_1 {
  meta:
    description = "datamaliciousorder - file Trojan.Autorun_Dump.Generic.Dacic.BC58E3CC.A.00D7D229_480_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "89dfe2e3e775130fd545fe867741081801ef1c7b93259de1fee5342f585f8393"

  strings:
    $s1 = "@DQv,hafT" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}