rule Virus_Hijack_Backdoor_Hangup_B_56_1 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Backdoor.Hangup.B_56_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "d933c70339a03843a99962526eb5dc76fea5a81a998689ceb82a60a2ff8d6efd"

  strings:
    $s1 = " MS Company. All rights reserved." fullword wide
    $s2 = " NTFS Check Utility" fullword wide

  condition:
    uint16(0) == 0x5a4d and
    all of them
}