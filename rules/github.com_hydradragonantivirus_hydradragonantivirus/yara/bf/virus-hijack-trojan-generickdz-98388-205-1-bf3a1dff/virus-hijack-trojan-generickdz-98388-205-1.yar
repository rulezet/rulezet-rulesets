rule Virus_Hijack_Trojan_GenericKDZ_98388_205_1 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Trojan.GenericKDZ.98388_205_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "5a55b547eb612162938edfecabb9cf66b04286f9ee3bb0c3a9d8b8d70d66fd4c"

  strings:
    $s1 = "mAKi{biv.-`" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}