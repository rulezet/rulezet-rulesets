rule Virus_Hijack_Trojan_GenericKDZ_74550_243_1 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Trojan.GenericKDZ.74550_243_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "0aadd3ec09dda36ad3b88ad9ec53c6f336411b3095bce0344c12ff673149dc7f"

  strings:
    $s1 = "tOGS:K" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}