rule Trojan_Autorun_Dump_Generic_Dacic_BC58E3CC_A_00D7D229_264_1 {
  meta:
    description = "datamaliciousorder - file Trojan.Autorun_Dump.Generic.Dacic.BC58E3CC.A.00D7D229_264_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "be0989584da4dc4fc214865da3b5b84f4aaca1e8bd3ec2f3e84c44c18818ce9e"

  strings:
    $s1 = ">iLearning Subscription: is defined as a web base" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}