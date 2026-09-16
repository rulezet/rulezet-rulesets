rule Virus_Hijack_Gen_Trojan_ShellObject_e8X_aian2n_15_1 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Gen.Trojan.ShellObject.e8X@aian2n_15_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "150177b9e87ccc2a69ba182037b868e8a38ffea87468b9cc559eb86104a8cce1"

  strings:
    $s1 = "Sainbox COM Support" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}