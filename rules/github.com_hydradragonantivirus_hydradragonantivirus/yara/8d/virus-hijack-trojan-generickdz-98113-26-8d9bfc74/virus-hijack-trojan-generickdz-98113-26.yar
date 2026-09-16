rule Virus_Hijack_Trojan_GenericKDZ_98113_26 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Trojan.GenericKDZ.98113_26.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "991d4ba87028cd5e953c882ae3d6c3ca6bc803960ab08bd14f76444c5a421700"

  strings:
    $s1 = "{Iby different names such as reseller, distributor" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}