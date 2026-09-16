rule Virus_Hijack_Dropped_Backdoor_Padodor_BJ_348 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Dropped.Backdoor.Padodor.BJ_348.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "c9b445ce05a00cb4a2db004b88c26f93f02afcde74d336dd2f74104acc68ad23"

  strings:
    $s1 = "ware a part of the software and may not be used s" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}