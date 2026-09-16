rule Virus_Hijack_Backdoor_Hangup_B_200 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Backdoor.Hangup.B_200.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "ecaba645db209faffb6e8e6b00be7d5d63872bed6707deeba67c8a930769b1a9"

  strings:
    $s1 = "=@your entire employee population." fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}