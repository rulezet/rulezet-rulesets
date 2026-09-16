rule Virus_Hijack_GenPack_Backdoor_Hangup_B_292 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_GenPack.Backdoor.Hangup.B_292.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "8bd478304d64e9e13bf22888b34a35f2029d3a6be094d6c86c4e43546e6bfe08"

  strings:
    $s1 = "Sto be invalid or unenforceable, the remaining provisions will remain effective. It is expressly agreed that the terms of this" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}