rule Virus_Hijack_Backdoor_Hangup_B_258 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Backdoor.Hangup.B_258.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "84eec758cd853c3181a0a686db776ec5fdab06813c59b591c7230b209d99867d"

  strings:
    $s1 = "rsoftware manually by Internet or telephone. In either case, Internet and telephone service charges may" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}