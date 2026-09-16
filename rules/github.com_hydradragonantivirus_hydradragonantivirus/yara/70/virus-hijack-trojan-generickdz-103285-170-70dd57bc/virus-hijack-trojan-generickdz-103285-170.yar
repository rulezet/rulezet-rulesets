rule Virus_Hijack_Trojan_GenericKDZ_103285_170 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Trojan.GenericKDZ.103285_170.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "73dfa3c0f204491f8986a2c0ecb8b26d9cc2f07d723906edc1d25d1e6161c688"

  strings:
    $s1 = "qpurposes of counting the number of processors which require licensing, a multicore chip with \"n\" processor cores shall be" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}