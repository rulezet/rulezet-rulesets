rule Virus_Hijack_Trojan_GenericKDZ_99416_45 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Trojan.GenericKDZ.99416_45.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "e61147e474e6bb6aed6aec09f91aee865abf63814d13071a82b26716383378f3"

  strings:
    $s1 = "K])TOHo" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}