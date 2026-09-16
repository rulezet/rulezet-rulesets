rule Trojan_Autorun_Dump_Generic_Dacic_BC58E3CC_A_00D7D229_207_1 {
  meta:
    description = "datamaliciousorder - file Trojan.Autorun_Dump.Generic.Dacic.BC58E3CC.A.00D7D229_207_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "c29990da9bf17f74026555266a99613e74fe5bb6bcf4c11ad4d122b1b65b28b4"

  strings:
    $s1 = "Oracle does not warrant that the Oracle Universi" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}