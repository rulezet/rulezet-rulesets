rule Virus_Hijack_Dropped_Backdoor_Padodor_BJ_44 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Dropped.Backdoor.Padodor.BJ_44.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "76de945710ad4ad3635f2836aece930a87e5372a10d8ee640dd3e89af7783697"

  strings:
    $s1 = "care a part of the software and may not be used s" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}