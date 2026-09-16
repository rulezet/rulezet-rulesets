rule Trojan_Autorun_Dump_Generic_Dacic_BC58E3CC_A_00D7D229_599_1 {
  meta:
    description = "datamaliciousorder - file Trojan.Autorun_Dump.Generic.Dacic.BC58E3CC.A.00D7D229_599_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "bc635eff087a3085f0a0f2af0b1d5da85d7d6aec650829759528f88fd2e23ef6"

  strings:
    $s1 = "KMProfessional User " fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}