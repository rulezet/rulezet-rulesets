rule Virus_Hijack_Gen_Trojan_ShellObject_g8W_aiHu4Wp_6 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Gen.Trojan.ShellObject.g8W@aiHu4Wp_6.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "ebce33bae1db12a6379a2681b9990f6edc0dd3c4b0645026a4c7989ff19e44b4"

  strings:
    $s1 = "WWhat if Microsoft breaches its warranty? If Microsoft breaches its limited warranty, your only" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}