rule Virus_Hijack_Trojan_GenericKDZ_105924_488_1 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Trojan.GenericKDZ.105924_488_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "4ff9c149fe193cb004e7012327fe0d05667c7446c50bc135c1b3943141e7a85e"

  strings:
    $s1 = ")}boSK@" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}