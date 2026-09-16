rule Trojan_Autorun_Dump_Generic_Dacic_BC58E3CC_A_00D7D229_162_1 {
  meta:
    description = "datamaliciousorder - file Trojan.Autorun_Dump.Generic.Dacic.BC58E3CC.A.00D7D229_162_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "b8e15852df55b48d53314cc879de3c8cb3e9713b2dbbf88670dca787261870f4"

  strings:
    $s1 = "07iLearning Subscription: is defined as a web base" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}