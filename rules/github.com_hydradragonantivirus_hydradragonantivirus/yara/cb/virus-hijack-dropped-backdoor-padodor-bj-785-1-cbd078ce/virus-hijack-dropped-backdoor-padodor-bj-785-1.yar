rule Virus_Hijack_Dropped_Backdoor_Padodor_BJ_785_1 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Dropped.Backdoor.Padodor.BJ_785_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "8cadb9629e529f60a8bdc5024c2d2db25e7f5346236ec669bf1a5de1cf34c289"

  strings:
    $s1 = "jointuress" fullword wide
    $s2 = "wheelrace" fullword wide
    $s3 = "griffonage" fullword wide

  condition:
    uint16(0) == 0x5a4d and
    all of them
}