rule Virus_Hijack_GenPack_Backdoor_Hangup_B_121 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_GenPack.Backdoor.Hangup.B_121.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "93bf86ec2afa6e3ea93f1381603e3c81b20802dca79c8ea9e3e20e3538921eae"

  strings:
    $s1 = "!software manually by Internet or telephone. In either case, Internet and telephone service charges may" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}