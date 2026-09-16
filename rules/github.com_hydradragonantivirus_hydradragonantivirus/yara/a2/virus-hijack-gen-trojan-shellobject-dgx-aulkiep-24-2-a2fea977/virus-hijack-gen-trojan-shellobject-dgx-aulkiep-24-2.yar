rule Virus_Hijack_Gen_Trojan_ShellObject_dGX_aulKiep_24_2 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Gen.Trojan.ShellObject.dGX@aulKiep_24_2.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "d1c3c6ced15f218827f32004abc2b70649ccc65b79d677c6eb9d7214a58ca5c8"

  strings:
    $s1 = "(NASi'" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}