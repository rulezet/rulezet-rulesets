rule Virus_Hijack_Gen_Trojan_ShellObject_f0W_aO3zEnn_2 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Gen.Trojan.ShellObject.f0W@aO3zEnn_2.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "5173240ab8ab9933e027dc21980c9d3c8681aa17231b94c4ec03d0403310a9fb"

  strings:
    $s1 = "j9dispute under this agreement to which Section B applies must be filed within one year in small claims" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}