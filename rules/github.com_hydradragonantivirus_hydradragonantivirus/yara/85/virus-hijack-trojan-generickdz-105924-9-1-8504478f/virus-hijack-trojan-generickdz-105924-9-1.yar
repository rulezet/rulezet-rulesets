rule Virus_Hijack_Trojan_GenericKDZ_105924_9_1 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Trojan.GenericKDZ.105924_9_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "47e8514667b59660de39bd011105bf31140f36bd3c409dbcb8fd62b22b4f3fd9"

  strings:
    $s1 = "bOrd:)" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}