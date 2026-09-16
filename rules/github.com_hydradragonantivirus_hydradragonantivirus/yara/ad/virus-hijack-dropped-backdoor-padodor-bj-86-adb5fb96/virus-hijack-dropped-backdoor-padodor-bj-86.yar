rule Virus_Hijack_Dropped_Backdoor_Padodor_BJ_86 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Dropped.Backdoor.Padodor.BJ_86.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "528b57904f90c6fa5ea9c5216e486968c1e971308630336cff5c4f6ee6d59b3a"

  strings:
    $s1 = "MMare a part of the software and may not be used s" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}