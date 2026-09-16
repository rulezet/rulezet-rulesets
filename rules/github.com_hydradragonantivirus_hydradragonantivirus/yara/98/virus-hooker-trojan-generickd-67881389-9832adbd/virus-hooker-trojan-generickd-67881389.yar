rule Virus_Hooker_Trojan_GenericKD_67881389 {
  meta:
    description = "datamaliciousorder - file Virus.Hooker_Trojan.GenericKD.67881389.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "75f51f3724cd3b69895f58c92a6413f627b00e2f95b07cd36b55c22a37024bea"

  strings:
    $s1 = "@~~@Windows Task Manager@~~@1@~~@" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}