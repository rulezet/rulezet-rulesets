rule Virus_Hijack_Trojan_GenericKDZ_103285_693 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Trojan.GenericKDZ.103285_693.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "8fe82a547832661eeca06752accaa0b3d0b7d08b120a9c74774b0b572267ff8d"

  strings:
    $s1 = "6University Online Library (" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}