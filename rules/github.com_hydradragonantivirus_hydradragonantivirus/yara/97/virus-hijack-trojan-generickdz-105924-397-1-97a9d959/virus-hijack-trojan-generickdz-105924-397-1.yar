rule Virus_Hijack_Trojan_GenericKDZ_105924_397_1 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Trojan.GenericKDZ.105924_397_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "7f6a193026ba526d14be772e3dcb53dc22caf86e14281070e8b94ac57b46b1e1"

  strings:
    $s1 = "SPur`P" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}