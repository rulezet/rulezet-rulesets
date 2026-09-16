rule Virus_Hijack_GenPack_Backdoor_Hangup_B_97_2 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_GenPack.Backdoor.Hangup.B_97_2.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "63ed383ce9b7dada247e5a9aebb501e8b52bbb31f85038c2a2ea623952eba71a"

  strings:
    $s1 = "nARY%U" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}