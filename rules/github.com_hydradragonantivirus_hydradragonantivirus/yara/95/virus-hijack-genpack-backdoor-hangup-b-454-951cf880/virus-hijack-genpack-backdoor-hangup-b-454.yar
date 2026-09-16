rule Virus_Hijack_GenPack_Backdoor_Hangup_B_454 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_GenPack.Backdoor.Hangup.B_454.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "11e06ba0db10b0822c3f0180d72fef10986cdb10f46364ca956fd59847e86178"

  strings:
    $s1 = "4to be invalid or unenforceable, the remaining provisions will remain effective. It is expressly agreed that the terms of this" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}