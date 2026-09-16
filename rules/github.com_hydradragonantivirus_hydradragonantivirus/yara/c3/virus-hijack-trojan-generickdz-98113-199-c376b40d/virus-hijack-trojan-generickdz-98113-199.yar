rule Virus_Hijack_Trojan_GenericKDZ_98113_199 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Trojan.GenericKDZ.98113_199.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "547d232b3afd172f6e723d2432db5528495476c4bdb585406cf156a664df7eff"

  strings:
    $s1 = "P$or service that is subject to a discount or a pr" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}