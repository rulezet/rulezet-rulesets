rule Trojan_Autorun_Dump_Generic_Dacic_BC58E3CC_A_00D7D229_122_1 {
  meta:
    description = "datamaliciousorder - file Trojan.Autorun_Dump.Generic.Dacic.BC58E3CC.A.00D7D229_122_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "b13ae268c27d345fc8c3ba42cdeeaba802fe00186fa2f24cb99172901fef0a53"

  strings:
    $s1 = "+iLearning Subscription: is defined as a web base" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}