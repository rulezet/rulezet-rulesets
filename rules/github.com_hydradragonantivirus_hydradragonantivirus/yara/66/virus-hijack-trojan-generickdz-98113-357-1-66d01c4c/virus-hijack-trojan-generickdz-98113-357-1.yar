rule Virus_Hijack_Trojan_GenericKDZ_98113_357_1 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Trojan.GenericKDZ.98113_357_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "47458db45c14927ad5a8c017b524545a0367eaf7a1aa377f5be5c218ecf98477"

  strings:
    $s1 = "ROle%`}" fullword ascii
    $s2 = "[AcoR " fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}