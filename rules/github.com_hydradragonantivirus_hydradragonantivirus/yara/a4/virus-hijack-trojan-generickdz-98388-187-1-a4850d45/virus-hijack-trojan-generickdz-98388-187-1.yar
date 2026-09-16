rule Virus_Hijack_Trojan_GenericKDZ_98388_187_1 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Trojan.GenericKDZ.98388_187_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "2b9dbaebd5e693c741fd2f864b13f93556a171ec579000322d795077b8fd9c9c"

  strings:
    $s1 = "CeTi&p" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}