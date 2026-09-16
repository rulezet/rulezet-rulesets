rule Virus_Hijack_Trojan_GenericKDZ_98113_94 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Trojan.GenericKDZ.98113_94.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "35bb69bf42761533b89c3f4268c1e5607749ef2c6fb165567170dead88f35f38"

  strings:
    $s1 = ";hundred euros) in all purchase orders transacted" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}