rule Virus_Hijack_Dropped_Backdoor_Padodor_BJ_442 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Dropped.Backdoor.Padodor.BJ_442.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "80de1b89b8b4ac071e9762deab9d010316b5519917a854ef297293f40fa5c742"

  strings:
    $s1 = "rGare a part of the software and may not be used s" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}