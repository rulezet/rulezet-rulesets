rule Virus_Hijack_Trojan_GenericKDZ_98113_163 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Trojan.GenericKDZ.98113_163.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "40b42a3da95000a5b003883962c11741ff5db619010c8438fc28c4612e8ceac4"

  strings:
    $s1 = "|by different names such as reseller, distributor" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}