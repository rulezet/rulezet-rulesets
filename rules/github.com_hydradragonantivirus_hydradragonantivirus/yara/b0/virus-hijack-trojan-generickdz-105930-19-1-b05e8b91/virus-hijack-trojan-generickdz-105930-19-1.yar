rule Virus_Hijack_Trojan_GenericKDZ_105930_19_1 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Trojan.GenericKDZ.105930_19_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "e3d3f690ed67a99f69cc0c6eb325da69bacbc458f0feed2444b722a0e4caad07"

  strings:
    $s1 = "POIl?T" fullword ascii
    $s2 = "Q+(greW" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}