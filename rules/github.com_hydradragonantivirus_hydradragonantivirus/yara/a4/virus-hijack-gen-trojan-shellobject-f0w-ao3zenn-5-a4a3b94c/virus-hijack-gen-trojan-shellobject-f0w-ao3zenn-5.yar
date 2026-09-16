rule Virus_Hijack_Gen_Trojan_ShellObject_f0W_aO3zEnn_5 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Gen.Trojan.ShellObject.f0W@aO3zEnn_5.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "f0c61dab8a7d0c54f452b8eeaa6f0f792c6d99e356ef4b8576e1f2fcdb8b8863"

  strings:
    $s1 = "PTdispute under this agreement to which Section B applies must be filed within one year in small claims" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}