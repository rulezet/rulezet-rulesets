rule Virus_Hijack_Trojan_GenericKDZ_103285_210 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Trojan.GenericKDZ.103285_210.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "07cfd6f19ea86275d9379f3dfe794ea6088245acef6d665e73bc65fda58555c3"

  strings:
    $s1 = "access the documentation online at http://oracle.com/contracts. Se" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}