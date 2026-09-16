rule Trojan_Autorun_Dump_Generic_Dacic_BC58E3CC_A_00D7D229_457_1 {
  meta:
    description = "datamaliciousorder - file Trojan.Autorun_Dump.Generic.Dacic.BC58E3CC.A.00D7D229_457_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "08a676b0c91b96d52ba96f77c0d7477fbdcbd6fcc3a563b94d9829262b4f45d3"

  strings:
    $s1 = "q8iLearning Subscription: is defined as a web base" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}