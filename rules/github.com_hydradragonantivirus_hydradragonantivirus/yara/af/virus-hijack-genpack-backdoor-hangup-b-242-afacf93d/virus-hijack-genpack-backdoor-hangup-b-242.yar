rule Virus_Hijack_GenPack_Backdoor_Hangup_B_242 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_GenPack.Backdoor.Hangup.B_242.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "caca02ce13261b68e33c3a9f2977335fb456e87e726cb0f21b9c1b5cf06531be"

  strings:
    $s1 = "!your entire employee population." fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}