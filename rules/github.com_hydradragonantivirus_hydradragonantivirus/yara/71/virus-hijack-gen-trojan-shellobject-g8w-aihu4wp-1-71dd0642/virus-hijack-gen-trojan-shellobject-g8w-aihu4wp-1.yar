rule Virus_Hijack_Gen_Trojan_ShellObject_g8W_aiHu4Wp_1 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Gen.Trojan.ShellObject.g8W@aiHu4Wp_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "0dc2ea172c8ce7155f3493fd01f2526c1b817d0c425eecaa3d3f57f8b394a407"

  strings:
    $s1 = "nWhat if Microsoft breaches its warranty? If Microsoft breaches its limited warranty, your only" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}