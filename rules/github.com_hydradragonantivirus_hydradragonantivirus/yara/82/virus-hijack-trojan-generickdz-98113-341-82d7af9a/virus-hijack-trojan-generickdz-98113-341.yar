rule Virus_Hijack_Trojan_GenericKDZ_98113_341 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Trojan.GenericKDZ.98113_341.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "6fcfeda5a274828df9306ecc3872536b2e58a962427d2d2d0de9ef814692c07d"

  strings:
    $s1 = "Nby different names such as reseller, distributor" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}