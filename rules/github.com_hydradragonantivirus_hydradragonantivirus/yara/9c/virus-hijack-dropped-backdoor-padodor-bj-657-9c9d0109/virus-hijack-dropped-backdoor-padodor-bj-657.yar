rule Virus_Hijack_Dropped_Backdoor_Padodor_BJ_657 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Dropped.Backdoor.Padodor.BJ_657.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "bb03c027f076acb7e8b07743dfaa369eb0762dd173408e63cd757cc98fef738a"

  strings:
    $s1 = "pand services at the list price in effect at the " fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}