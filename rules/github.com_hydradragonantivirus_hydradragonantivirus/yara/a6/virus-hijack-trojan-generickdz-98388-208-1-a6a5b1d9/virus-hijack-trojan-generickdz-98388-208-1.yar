rule Virus_Hijack_Trojan_GenericKDZ_98388_208_1 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Trojan.GenericKDZ.98388_208_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "1a4327c5b2a8580f21237cd36102ec3458666c44680ba5a7faf7e05a6ccdfdd1"

  strings:
    $s1 = "av vENT" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}