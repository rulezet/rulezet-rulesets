rule Virus_Hijack_GenPack_Backdoor_Hangup_B_182 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_GenPack.Backdoor.Hangup.B_182.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "a6d2867be752d1cf5f54e48f80b3f6ab2604f7fa979a0d7e6c0874ae5d08d573"

  strings:
    $s1 = "9?to be invalid or unenforceable, the remaining provisions will remain effective. It is expressly agreed that the terms of this" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}