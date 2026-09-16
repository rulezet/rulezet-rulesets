rule Virus_Hijack_Gen_Trojan_ShellObject_e8X_aa9T7Ob_8 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Gen.Trojan.ShellObject.e8X@aa9T7Ob_8.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "29b2b2aec93deab8d6fc72a8c7483162ca721b5a60a646d959dd877095cc6e0e"

  strings:
    $s1 = "mhundred euros) in all purchase orders transacted" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}