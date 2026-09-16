rule Virus_Hijack_Trojan_GenericKDZ_105920_15_1 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Trojan.GenericKDZ.105920_15_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "f7e30bb047d0fb1ee3758624b059fb2cd706eec3c987e5040b06f9187be9773a"

  strings:
    $s1 = "Z#sORt" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}