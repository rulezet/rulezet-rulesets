rule Trojan_Autorun_Dump_Generic_Dacic_BC58E3CC_A_00D7D229_157_1 {
  meta:
    description = "datamaliciousorder - file Trojan.Autorun_Dump.Generic.Dacic.BC58E3CC.A.00D7D229_157_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "b45c3124a549091df95f196d2d2b3b523abcc4dafbac89ed9829be4eb3aaaeaf"

  strings:
    $s1 = "rOracle does not warrant that the Oracle Universi" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}