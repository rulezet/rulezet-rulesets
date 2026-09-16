rule Trojan_Autorun_Dump_Generic_Dacic_BC58E3CC_A_00D7D229_461_1 {
  meta:
    description = "datamaliciousorder - file Trojan.Autorun_Dump.Generic.Dacic.BC58E3CC.A.00D7D229_461_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "577713bf1f473947488bcb52062859202aca2c647e4aed75e91ecaac9bfd0046"

  strings:
    $s1 = "'RiLearning Subscription: is defined as a web base" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}