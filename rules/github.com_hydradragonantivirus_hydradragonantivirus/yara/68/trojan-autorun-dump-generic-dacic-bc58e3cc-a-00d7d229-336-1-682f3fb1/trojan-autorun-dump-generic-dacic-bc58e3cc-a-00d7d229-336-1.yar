rule Trojan_Autorun_Dump_Generic_Dacic_BC58E3CC_A_00D7D229_336_1 {
  meta:
    description = "datamaliciousorder - file Trojan.Autorun_Dump.Generic.Dacic.BC58E3CC.A.00D7D229_336_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "1f82b4f1e8028cd9d9d7597d5f9d2d3a70a0e7e9b420266b8f7a818fbb6c74c0"

  strings:
    $s1 = "caOracle does not warrant that the Oracle Universi" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}