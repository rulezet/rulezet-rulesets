rule Virus_Hijack_Backdoor_Hangup_B_283_1 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Backdoor.Hangup.B_283_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "e6859d8e5503cb30a194078f781db32cf32b4a77af53da9a816a1d003722d0a0"

  strings:
    $s1 = "Virtual@L" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}