rule Virus_Hijack_Gen_Trojan_ShellObject_f0W_aO3zEnn_13 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Gen.Trojan.ShellObject.f0W@aO3zEnn_13.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "1d4f9035705b6d2424b80b3795f04d58bb3ce1a2dbdea9ce5edd801e1a6de7cc"

  strings:
    $s1 = "<sdispute under this agreement to which Section B applies must be filed within one year in small claims" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}