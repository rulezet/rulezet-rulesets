rule Virus_Hijack_Trojan_GenericKDZ_98113_342 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Trojan.GenericKDZ.98113_342.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "e7977106967db8b5804d677165c962666fb42eeb32491d58b2a84bd79c4c8883"

  strings:
    $s1 = "Hassets, owned or managed for others, which were " fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}