rule Virus_Hijack_Trojan_GenericKDZ_98113_70_1 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Trojan.GenericKDZ.98113_70_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "ba32449d3c7dcf47c445205e0ec4d83831c19729a31538f17eed52f5de2627eb"

  strings:
    $s1 = "$VEIN{c%K" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}