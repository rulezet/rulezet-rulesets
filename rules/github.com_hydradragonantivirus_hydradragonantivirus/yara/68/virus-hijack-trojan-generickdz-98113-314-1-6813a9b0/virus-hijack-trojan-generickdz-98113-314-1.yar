rule Virus_Hijack_Trojan_GenericKDZ_98113_314_1 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Trojan.GenericKDZ.98113_314_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "35c7c1880af65c2cbd57859e2ac6db6438f90f555d45ceac3b5e0d617655d326"

  strings:
    $s1 = "LOTa`+" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}