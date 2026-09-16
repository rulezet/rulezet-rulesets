rule Virus_Hijack_Trojan_GenericKDZ_79663_96_1 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Trojan.GenericKDZ.79663_96_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "cc2ff7e6002ba6d0a7c6676f4bec9ab49d58a694b8ce5ce7cd8f2e65b0352deb"

  strings:
    $s1 = "F;)TAsK}6" fullword ascii
    $s2 = "r(rOId" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}