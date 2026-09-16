rule Virus_Hijack_GenPack_Backdoor_Hangup_B_8 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_GenPack.Backdoor.Hangup.B_8.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "0444369e557fa02a3beee23d0fc30f816724bad5e6f1d3beb9e4730aaeefeddb"

  strings:
    $s1 = "<Professional User " fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}