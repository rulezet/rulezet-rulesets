rule Virus_Hijack_GenPack_Backdoor_Hangup_B_80 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_GenPack.Backdoor.Hangup.B_80.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "4dda626daf20436e82b569f20060f40faadc6d9349f6a55bf40f39d0fe2bc13e"

  strings:
    $s1 = "(your entire employee population." fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}