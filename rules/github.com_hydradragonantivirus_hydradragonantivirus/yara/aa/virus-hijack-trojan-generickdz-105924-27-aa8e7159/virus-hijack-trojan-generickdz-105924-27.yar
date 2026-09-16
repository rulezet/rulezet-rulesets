rule Virus_Hijack_Trojan_GenericKDZ_105924_27 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Trojan.GenericKDZ.105924_27.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "d03f68e6cc6fc9e5431831cd99cea628d592d296e66c2cc0e96dc1a3562d77b6"

  strings:
    $s1 = "Q)sOCo#" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}