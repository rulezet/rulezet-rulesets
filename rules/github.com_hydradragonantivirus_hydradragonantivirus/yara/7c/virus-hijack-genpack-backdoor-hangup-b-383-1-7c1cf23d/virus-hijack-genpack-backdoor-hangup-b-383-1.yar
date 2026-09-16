rule Virus_Hijack_GenPack_Backdoor_Hangup_B_383_1 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_GenPack.Backdoor.Hangup.B_383_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "e98ee019307d57d60376490c38f9a02aa1775fa7b0055687c6e4bb124c4d83b3"

  strings:
    $s1 = "2.1 Default RGB colour space " fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}