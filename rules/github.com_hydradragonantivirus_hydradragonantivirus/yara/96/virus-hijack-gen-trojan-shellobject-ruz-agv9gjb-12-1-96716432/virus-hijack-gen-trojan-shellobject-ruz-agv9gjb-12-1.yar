rule Virus_Hijack_Gen_Trojan_ShellObject_ruZ_aGV9gJb_12_1 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Gen.Trojan.ShellObject.ruZ@aGV9gJb_12_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "5b43548924225ec89f1122b6b91106a539f5e4252029c1f8b17e213cd35d4535"

  strings:
    $s1 = "ADATi$Z" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}