rule Virus_Hijack_Gen_Trojan_ShellObject_ruZ_aiy413e_5_1 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Gen.Trojan.ShellObject.ruZ@aiy413e_5_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "bcccd151e6436985d9462aa5192d9d6a4e56a337dcb23d4fd8b8f77bd647acd1"

  strings:
    $s1 = "biNe(z <" fullword ascii
    $s2 = "WRAn$tm" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}