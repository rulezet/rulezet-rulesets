rule Virus_Hijack_Gen_Trojan_ShellObject_g8X_aK5_lZo_4 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Gen.Trojan.ShellObject.g8X@aK5!lZo_4.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "d4a196890405ca158b4b73edf4dac4dd8fbff2e82c2c6d73db363f2d82464c1a"

  strings:
    $s1 = "hUniversity Online Library (" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}