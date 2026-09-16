rule Virus_Hijack_Trojan_EmotetU_Gen_n00_heQRMgbi {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Trojan.EmotetU.Gen.n00@heQRMgbi.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "ce9cfed3c75968c67a7e85534e165e58a8f31ad5bc6a1c7c9731657380dbd4d4"

  strings:
    $s1 = "underfeeling" fullword wide
    $s2 = "Morrowmass" fullword wide
    $s3 = "Abstractiveness" fullword wide
    $s4 = "HALA@ED" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}