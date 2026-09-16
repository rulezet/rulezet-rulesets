rule Virus_Hijack_Trojan_GenericKDZ_98113_297_1 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Trojan.GenericKDZ.98113_297_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "97b1ee89538da5cecbd773305a7dd0fd60dcc77a6e902ad85946f27a0f3d0f60"

  strings:
    $s1 = ")!piCt" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}