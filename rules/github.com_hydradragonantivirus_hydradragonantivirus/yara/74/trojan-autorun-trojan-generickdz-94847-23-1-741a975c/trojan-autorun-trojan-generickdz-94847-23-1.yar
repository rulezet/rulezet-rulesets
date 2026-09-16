rule Trojan_Autorun_Trojan_GenericKDZ_94847_23_1 {
  meta:
    description = "datamaliciousorder - file Trojan.Autorun_Trojan.GenericKDZ.94847_23_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "eb518d66dc7608b007cd56b6b65dbcd5d153586aab903d3e6ba1b44adac30705"

  strings:
    $s1 = "sLip'L>" fullword ascii
    $s2 = "BLip%M" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}