rule Virus_Hijack_Trojan_GenericKDZ_79663_122_1 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Trojan.GenericKDZ.79663_122_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "8549e716473d8e90eefadb8dddae5248e85a8058b7f09197ca85ee8a98acca60"

  strings:
    $s1 = "+$fIat" fullword ascii
    $s2 = "o!zEmI" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}