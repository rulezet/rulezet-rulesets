rule Virus_Hijack_Dropped_Backdoor_Padodor_BJ_476 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Dropped.Backdoor.Padodor.BJ_476.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "e3e3b485e89bff5dca88b4ddfa93581bb06076eb1e7f02bf5c677140dedc1cfb"

  strings:
    $s1 = "`xIsE.0`SIsE.0" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}