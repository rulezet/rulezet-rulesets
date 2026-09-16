rule Virus_Hijack_Trojan_GenericKDZ_98113_231_1 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Trojan.GenericKDZ.98113_231_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "84450c536fd4285fa3c33166f1aa7ba7fe0032b85214184e77348a25ec32a1d1"

  strings:
    $s1 = "sons:Zy," fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}