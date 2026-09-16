rule Virus_Hijack_GenPack_Backdoor_Hangup_B_286 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_GenPack.Backdoor.Hangup.B_286.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "05268d388909e8cf96c1a1978c8ad0d7a779a2a599088f92ebd0a4629bfbc00a"

  strings:
    $s1 = "\"your entire employee population." fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}