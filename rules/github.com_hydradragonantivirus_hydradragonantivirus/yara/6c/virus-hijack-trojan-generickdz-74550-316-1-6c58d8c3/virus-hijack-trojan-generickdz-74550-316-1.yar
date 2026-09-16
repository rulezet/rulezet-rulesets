rule Virus_Hijack_Trojan_GenericKDZ_74550_316_1 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Trojan.GenericKDZ.74550_316_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "14829b22a106ebd43ceb5a2c27d1b2f05f1bc87ae0cecb1a565b8fa2e9f47884"

  strings:
    $s1 = "u,cokY" fullword ascii
    $s2 = "mF?vInO" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}