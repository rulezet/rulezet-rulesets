rule Trojan_Autorun_Dump_Generic_Dacic_BC58E3CC_A_00D7D229_423_1 {
  meta:
    description = "datamaliciousorder - file Trojan.Autorun_Dump.Generic.Dacic.BC58E3CC.A.00D7D229_423_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "6e8fbf0796e2558e477492b746186c2af71692a432085e42646dacb31e691ca4"

  strings:
    $s1 = "YiLearning Subscription: is defined as a web base" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}