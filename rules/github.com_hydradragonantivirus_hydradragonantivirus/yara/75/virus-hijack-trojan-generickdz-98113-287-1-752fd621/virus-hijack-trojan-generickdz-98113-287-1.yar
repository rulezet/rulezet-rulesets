rule Virus_Hijack_Trojan_GenericKDZ_98113_287_1 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Trojan.GenericKDZ.98113_287_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "e5be6b3d94f7089f6210e5b02a2b5ff9022965ca338224db8ffafb3664c6b59e"

  strings:
    $s1 = "SKey*Nw" fullword ascii
    $s2 = "COPpY." fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}