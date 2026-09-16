rule Virus_Hijack_Gen_Trojan_ShellObject_g8X_aiHu4Wp_25 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Gen.Trojan.ShellObject.g8X@aiHu4Wp_25.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "0c6f57724d1a37ae8f26cb7b0e95451ad4feaedc9670407f18739d339ad4c7fe"

  strings:
    $s1 = "kWhat if Microsoft breaches its warranty? If Microsoft breaches its limited warranty, your only" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}