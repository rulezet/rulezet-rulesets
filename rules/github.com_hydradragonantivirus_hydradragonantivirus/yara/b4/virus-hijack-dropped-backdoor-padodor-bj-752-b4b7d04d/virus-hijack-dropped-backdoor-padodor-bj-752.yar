rule Virus_Hijack_Dropped_Backdoor_Padodor_BJ_752 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Dropped.Backdoor.Padodor.BJ_752.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "87903abbeb4b942e0d82e07f4dabeb026bdb7d0f1a0c32f0d1a3cb950d2315a0"

  strings:
    $s1 = ":aare a part of the software and may not be used s" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}