rule Virus_Hijack_Trojan_GenericKDZ_79663_14 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Trojan.GenericKDZ.79663_14.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "9812ac9ca27caddd3997088e4c83e6a043fdc1f0206fdee81ebf7bd02fa5e2ca"

  strings:
    $s1 = "this notice will include a copy of your agreemen" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}