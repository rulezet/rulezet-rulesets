rule Virus_Hijack_Dropped_Backdoor_Padodor_BJ_220 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Dropped.Backdoor.Padodor.BJ_220.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "d52b58c1c16c78ec83837249672342545d5556b60fb6f81df15617b37acde730"

  strings:
    $s1 = "uMicrosoft Ireland Operations Limited makes the l" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}