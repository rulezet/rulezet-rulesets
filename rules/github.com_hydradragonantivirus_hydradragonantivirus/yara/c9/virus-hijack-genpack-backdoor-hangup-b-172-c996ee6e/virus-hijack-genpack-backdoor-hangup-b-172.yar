rule Virus_Hijack_GenPack_Backdoor_Hangup_B_172 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_GenPack.Backdoor.Hangup.B_172.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "8fe0e4bdedb3d4380def03e78939bfd26c9db14bb2eb87c2e0283db505cb4f40"

  strings:
    $s1 = "A2013 software. For your convenience, we" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}