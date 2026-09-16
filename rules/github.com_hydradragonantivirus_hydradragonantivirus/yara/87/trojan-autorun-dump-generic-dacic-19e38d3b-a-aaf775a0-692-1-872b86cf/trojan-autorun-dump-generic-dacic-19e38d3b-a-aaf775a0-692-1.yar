rule Trojan_Autorun_Dump_Generic_Dacic_19E38D3B_A_AAF775A0_692_1 {
  meta:
    description = "datamaliciousorder - file Trojan.Autorun_Dump.Generic.Dacic.19E38D3B.A.AAF775A0_692_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "89f7a51dc82332c4f1dd0886dd92a3790ca556662c7406441558fa313f4bcfda"

  strings:
    $s1 = "yiLearning Subscription: is defined as a web base" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}