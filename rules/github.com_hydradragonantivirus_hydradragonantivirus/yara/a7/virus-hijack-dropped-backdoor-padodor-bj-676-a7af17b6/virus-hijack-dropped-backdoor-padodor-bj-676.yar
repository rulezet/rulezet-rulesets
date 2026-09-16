rule Virus_Hijack_Dropped_Backdoor_Padodor_BJ_676 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Dropped.Backdoor.Padodor.BJ_676.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "ab064052e15060d4c70d9057b9a453536362b6edbb54bd96e161e3cdc7baae4b"

  strings:
    $s1 = "vfIf you want to find out more about academic soft" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}