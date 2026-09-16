rule Virus_Hijack_GenPack_Backdoor_Hangup_B_278 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_GenPack.Backdoor.Hangup.B_278.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "9d6809760ca9b4869763be6c73645c4c58cce93e53ce66032912520372d0fe4e"

  strings:
    $s1 = "ycreate this contract that applies to you. You can review linked terms by pasting the forward link into your" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}