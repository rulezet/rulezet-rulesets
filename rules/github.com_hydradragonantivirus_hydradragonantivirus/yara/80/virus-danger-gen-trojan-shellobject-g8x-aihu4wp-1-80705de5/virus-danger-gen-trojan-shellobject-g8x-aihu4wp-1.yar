rule Virus_Danger_Gen_Trojan_ShellObject_g8X_aiHu4Wp_1 {
  meta:
    description = "datamaliciousorder - file Virus.Danger_Gen.Trojan.ShellObject.g8X@aiHu4Wp_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "823d3b65f041f4ab7330a177b4654b4f3c9c31deebc525e00e2b1c73d3eaba59"

  strings:
    $s1 = "yWhat if Microsoft breaches its warranty? If Microsoft breaches its limited warranty, your only" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}