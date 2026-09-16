rule Virus_Hijack_Trojan_GenericKDZ_105930_22 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Trojan.GenericKDZ.105930_22.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "63bda324ec0c6c5360a58d0634796af20aa5f2d68a679b66c1fac9ec880f5b2e"

  strings:
    $s1 = "yOUR LICE" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}