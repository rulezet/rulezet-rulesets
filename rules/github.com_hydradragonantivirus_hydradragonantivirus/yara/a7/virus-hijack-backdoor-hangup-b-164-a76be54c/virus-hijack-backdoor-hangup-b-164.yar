rule Virus_Hijack_Backdoor_Hangup_B_164 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Backdoor.Hangup.B_164.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "57e3e623e156e5646b09d0e322e64cd0967671c57a47e5456ec395e8325b7aeb"

  strings:
    $s1 = "Kyour entire employee population." fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}