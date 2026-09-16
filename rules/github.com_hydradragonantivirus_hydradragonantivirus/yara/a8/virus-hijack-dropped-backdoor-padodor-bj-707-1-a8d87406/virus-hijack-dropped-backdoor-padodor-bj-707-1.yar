rule Virus_Hijack_Dropped_Backdoor_Padodor_BJ_707_1 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Dropped.Backdoor.Padodor.BJ_707_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "a34c88fed6bc3eba3366d7e9724943d0a23509fe01949a63e09b53c70367ce0c"

  strings:
    $s1 = ")\"(null)" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}