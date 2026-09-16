rule Virus_Hijack_Trojan_GenericKDZ_79663_93_1 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Trojan.GenericKDZ.79663_93_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "d8db173334b831dc3e5d80cfcfbff09686c4a9e5dcfebba82064b7acbda43bf3"

  strings:
    $s1 = "M)BIck" fullword ascii
    $s2 = "x@OGle" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}