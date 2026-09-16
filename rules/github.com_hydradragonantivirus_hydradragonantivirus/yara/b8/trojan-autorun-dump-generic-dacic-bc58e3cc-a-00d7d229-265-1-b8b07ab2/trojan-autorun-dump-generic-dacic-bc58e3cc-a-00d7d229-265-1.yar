rule Trojan_Autorun_Dump_Generic_Dacic_BC58E3CC_A_00D7D229_265_1 {
  meta:
    description = "datamaliciousorder - file Trojan.Autorun_Dump.Generic.Dacic.BC58E3CC.A.00D7D229_265_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "aeb0088117c58d66c42d7200ecd856cbd999876a6a48574b57806157a3453f31"

  strings:
    $s1 = "of Subscribers. If your busines" fullword ascii
    $s2 = "scyT:S" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}