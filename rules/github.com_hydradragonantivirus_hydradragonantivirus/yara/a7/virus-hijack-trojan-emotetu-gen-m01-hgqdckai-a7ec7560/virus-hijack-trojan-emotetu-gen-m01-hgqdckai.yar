rule Virus_Hijack_Trojan_EmotetU_Gen_m01_hGQdcKai {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Trojan.EmotetU.Gen.m01@hGQdcKai.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "0c62216fe8650dcf5482d0d4877d53c7e056b8c80199b178500750de517a1fcb"

  strings:
    $s1 = "frownful" fullword wide
    $s2 = "conservant" fullword wide

  condition:
    uint16(0) == 0x5a4d and
    all of them
}