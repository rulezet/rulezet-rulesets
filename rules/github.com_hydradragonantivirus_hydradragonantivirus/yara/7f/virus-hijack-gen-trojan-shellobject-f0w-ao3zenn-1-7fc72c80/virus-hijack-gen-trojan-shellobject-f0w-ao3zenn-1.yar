rule Virus_Hijack_Gen_Trojan_ShellObject_f0W_aO3zEnn_1 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Gen.Trojan.ShellObject.f0W@aO3zEnn_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "8491a0bc3d53c2be2d9a92f944501972801e7e4945225def3152dca508f24756"

  strings:
    $s1 = "kdispute under this agreement to which Section B applies must be filed within one year in small claims" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}