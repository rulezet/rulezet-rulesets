rule Virus_Hijack_Dropped_Backdoor_Padodor_BJ_119 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Dropped.Backdoor.Padodor.BJ_119.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "8d9a82f365b9526ba2ac112df30e437601ce70ab43f348ba5ddd3a7f50d12e78"

  strings:
    $s1 = "jand services at the list price in effect at the " fullword ascii
    $s2 = "infringement claim could have been avoided by`" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}