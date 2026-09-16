rule Virus_Hijack_Trojan_GenericKDZ_98113_223 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Trojan.GenericKDZ.98113_223.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "f3d5e393b6179b3fe5a09cc1117008d7c5a6b6c84c367b27dc139f699412d69b"

  strings:
    $s1 = "Yassets, owned or managed for others, which were " fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}