rule Virus_Hijack_Dropped_Backdoor_Padodor_BJ_382 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Dropped.Backdoor.Padodor.BJ_382.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "c4a3405642e1e02d34a93f4333c3296a10b9bbad14307675119fb2f58facc033"

  strings:
    $s1 = "nare a part of the software and may not be used s" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}