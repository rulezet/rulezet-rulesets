rule Virus_Hijack_Dropped_Backdoor_Padodor_BJ_596 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Dropped.Backdoor.Padodor.BJ_596.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "c6d10f75952cbd85d736e6270680b8ba49e86d8768ea557561c4514931aec283"

  strings:
    $s1 = "@9are a part of the software and may not be used s" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}