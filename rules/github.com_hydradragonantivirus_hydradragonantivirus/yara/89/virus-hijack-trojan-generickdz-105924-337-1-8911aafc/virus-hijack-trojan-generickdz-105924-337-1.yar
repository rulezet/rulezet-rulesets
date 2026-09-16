rule Virus_Hijack_Trojan_GenericKDZ_105924_337_1 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Trojan.GenericKDZ.105924_337_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "0d086442307f2f4a01e6e96386dc423aa1d7f4c12dd8bb7173e100a3115e0104"

  strings:
    $s1 = "croC:}26" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}