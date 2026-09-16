rule Virus_Hijack_Trojan_GenericKDZ_98113_253_1 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Trojan.GenericKDZ.98113_253_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "53a231fd6aaca6e00d1159f84ded2cb0aa71931a5a06b05a6c528e916816bd7b"

  strings:
    $s1 = "((ToAd" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}