rule Virus_Hijack_Gen_Trojan_ShellObject_g8X_aiHu4Wp_14 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Gen.Trojan.ShellObject.g8X@aiHu4Wp_14.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "f9ef1321d88a5e2616d4e2db6c2d6a38fd9b264db3931beee919935d798ddd8d"

  strings:
    $s1 = "mWhat if Microsoft breaches its warranty? If Microsoft breaches its limited warranty, your only" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}