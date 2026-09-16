rule Virus_Hijack_Backdoor_Hangup_B_76 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Backdoor.Hangup.B_76.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "3e75885ba1d3576746bc465b90f1ebdf39bc9c1b649af843b739f0e721335aca"

  strings:
    $s1 = "lORn$O" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}