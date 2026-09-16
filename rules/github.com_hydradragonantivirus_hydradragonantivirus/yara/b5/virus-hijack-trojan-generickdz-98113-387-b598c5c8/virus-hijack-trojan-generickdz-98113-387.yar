rule Virus_Hijack_Trojan_GenericKDZ_98113_387 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Trojan.GenericKDZ.98113_387.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "ca34512d727d7082983eadc000fedf2fffb77359d0ad6fb06e9b9b5a76de6255"

  strings:
    $s1 = "Ihundred euros) in all purchase orders transacted" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}