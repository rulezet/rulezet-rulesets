rule Trojan_Autorun_Dump_Generic_Dacic_BC58E3CC_A_00D7D229_271_1 {
  meta:
    description = "datamaliciousorder - file Trojan.Autorun_Dump.Generic.Dacic.BC58E3CC.A.00D7D229_271_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "77db5927ed1a1c3dd31cdebb7d48b96b59ca8ec31b8c425b59a6486860ebde74"

  strings:
    $s1 = "HiLearning Subscription: is defined as a web base" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}