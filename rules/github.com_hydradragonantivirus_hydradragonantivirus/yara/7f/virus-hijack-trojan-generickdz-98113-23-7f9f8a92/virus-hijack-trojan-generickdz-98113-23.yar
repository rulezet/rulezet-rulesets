rule Virus_Hijack_Trojan_GenericKDZ_98113_23 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Trojan.GenericKDZ.98113_23.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "01c49f52c49e54d064418932a4b550e6df5e30f9d8d8f6adaf261b37f8050a19"

  strings:
    $s1 = "e<ruPa" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}