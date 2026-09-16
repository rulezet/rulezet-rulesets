rule Virus_Hijack_Trojan_GenericKDZ_98113_78 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Trojan.GenericKDZ.98113_78.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "2b330d25de1446407f1d4b55d68059e35eaa4773ba074f7128061fc3c59b5143"

  strings:
    $s1 = "@by different names such as reseller, distributor" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}