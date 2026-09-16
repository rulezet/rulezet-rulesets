rule Virus_Hijack_Gen_Trojan_ShellObject_f8X_aG5Bc5o_2 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Gen.Trojan.ShellObject.f8X@aG5Bc5o_2.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "159ed803706b523a3dc45ab9c2c6ddad7a51b3f8a11bf0ceb92c31d01d5874a5"

  strings:
    $s1 = "jhundred euros) in all purchase orders transacted" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}