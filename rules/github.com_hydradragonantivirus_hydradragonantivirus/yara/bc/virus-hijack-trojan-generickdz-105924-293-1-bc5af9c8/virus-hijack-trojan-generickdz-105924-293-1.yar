rule Virus_Hijack_Trojan_GenericKDZ_105924_293_1 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Trojan.GenericKDZ.105924_293_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "e9da75de3e7e2d109b8ba77b8817385ff4d176c8cc491ac8a9c65d0f3241922c"

  strings:
    $s1 = "!u?lACY" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}