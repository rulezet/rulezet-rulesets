rule Virus_Hijack_Backdoor_Hangup_B_302 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Backdoor.Hangup.B_302.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "7e154f4aefd2ad9cfb880be0487407127d66333f2a22fbdc57046136a8e4115f"

  strings:
    $s1 = "bcounted as \"n\" processors. For the Healthcare Transaction Base program, only the processors on which Internet Application" fullword ascii
    $s2 = "student enrolled in your institution counts as 25% of" fullword ascii
    $s3 = "?|@thuD" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}