rule Virus_Hijack_Trojan_GenericKDZ_98113_51_1 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Trojan.GenericKDZ.98113_51_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "e2eb50c539ced68622e4eb974e3fac8b10405c787448983705c41c1f6617ecaf"

  strings:
    $s1 = "<pOuT[" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}