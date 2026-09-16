rule Virus_Hijack_Backdoor_Hangup_B_112 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Backdoor.Hangup.B_112.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "74d37e9e8af51b2a11bab3fb528b68dd2512d86ba2275579cf365d7d94cf37ab"

  strings:
    $s1 = "hcyour entire employee population." fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}