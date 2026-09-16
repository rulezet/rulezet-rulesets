rule Virus_Hijack_Dropped_Backdoor_Padodor_BJ_528 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Dropped.Backdoor.Padodor.BJ_528.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "81800590c2238221c6f94959b1d43dbf54c937966f4512017cbf27ce96ce6a9d"

  strings:
    $s1 = "GZare a part of the software and may not be used s" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}