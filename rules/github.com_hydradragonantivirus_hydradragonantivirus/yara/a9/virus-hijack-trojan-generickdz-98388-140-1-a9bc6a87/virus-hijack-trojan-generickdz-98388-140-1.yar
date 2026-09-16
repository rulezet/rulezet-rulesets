rule Virus_Hijack_Trojan_GenericKDZ_98388_140_1 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Trojan.GenericKDZ.98388_140_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "d2d9b0395c4dc938672fb38213f8a29343c632cc40deaea9833520416079bcb3"

  strings:
    $s1 = "whAT*c" fullword ascii
    $s2 = "boob.}" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}