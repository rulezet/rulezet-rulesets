rule Virus_Hijack_Trojan_GenericKDZ_105930_32 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Trojan.GenericKDZ.105930_32.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "5fc8b1fe5aa4edc37d2301bb9869e73c767f9196b37255de35054c845a450e69"

  strings:
    $s1 = "sIgH@J^" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}