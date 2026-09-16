rule Virus_Hijack_Dropped_Backdoor_Padodor_BJ_471 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Dropped.Backdoor.Padodor.BJ_471.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "4cde8669f9cf280ee5131e9dbceb7a794681c0bc31b84da50775874624231583"

  strings:
    $s1 = "infringement claim could have been avoided by`" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}