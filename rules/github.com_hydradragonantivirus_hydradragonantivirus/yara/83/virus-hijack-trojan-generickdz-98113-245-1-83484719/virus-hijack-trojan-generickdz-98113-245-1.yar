rule Virus_Hijack_Trojan_GenericKDZ_98113_245_1 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Trojan.GenericKDZ.98113_245_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "782f5a0b3ed94fb206cccb1435458c432c742c09e0141e824ec36750eab89b77"

  strings:
    $s1 = "pOkY&i" fullword ascii
    $s2 = "s[CHOW" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}