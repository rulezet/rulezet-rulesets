rule Virus_Hijack_Trojan_GenericKDZ_103545_22 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Trojan.GenericKDZ.103545_22.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "fb091a0473d2234a91d5fbe6f76aef09571906b6e28e4b824a4c29db4cf07b42"

  strings:
    $s1 = "zsoftware features to upgrade or fix the software and otherwise improve its products and services. In" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}