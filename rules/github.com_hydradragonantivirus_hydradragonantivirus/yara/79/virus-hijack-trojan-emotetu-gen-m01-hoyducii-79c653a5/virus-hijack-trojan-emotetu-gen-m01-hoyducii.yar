rule Virus_Hijack_Trojan_EmotetU_Gen_m01_hOyDUCii {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Trojan.EmotetU.Gen.m01@hOyDUCii.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "849db9c5089501db7961a2c18e35695e7c8dbf18b988c794298344744bf51b14"

  strings:
    $s1 = "frownful" fullword wide
    $s2 = "conservant" fullword wide

  condition:
    uint16(0) == 0x5a4d and
    all of them
}