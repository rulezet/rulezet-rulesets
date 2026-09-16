rule Virus_Hijack_Trojan_GenericKDZ_98388_9 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Trojan.GenericKDZ.98388_9.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "9c135c97791b979ee0cdcc80498c21aa7b7c12b51324950ad11dd48b28cf0fe7"

  strings:
    $s1 = "*kAGo;" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}