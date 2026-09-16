rule Trojan_Autorun_Dump_Generic_Dacic_BC58E3CC_A_00D7D229_409_1 {
  meta:
    description = "datamaliciousorder - file Trojan.Autorun_Dump.Generic.Dacic.BC58E3CC.A.00D7D229_409_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "5bf9a6a4735bae7b8aedf76380a68012c81b116d2c207038a7c12a44239b9c27"

  strings:
    $s1 = "DBiLearning Subscription: is defined as a web base" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}