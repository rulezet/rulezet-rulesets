rule Virus_Hijack_Trojan_GenericKDZ_98113_267_1 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Trojan.GenericKDZ.98113_267_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "704a72a057ff6d2b157fec07125a446d19a655b7236ade81e78443e11a1c390e"

  strings:
    $s1 = ">8P\"FrAt" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}