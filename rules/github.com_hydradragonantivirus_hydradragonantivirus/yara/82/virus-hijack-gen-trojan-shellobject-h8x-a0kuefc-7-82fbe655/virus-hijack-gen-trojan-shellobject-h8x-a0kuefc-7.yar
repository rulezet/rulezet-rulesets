rule Virus_Hijack_Gen_Trojan_ShellObject_h8X_a0kuefc_7 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Gen.Trojan.ShellObject.h8X@a0kuefc_7.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "aff5f7cd51a85d3a6c198b077435af7a53cbad74d76719b6d3afaf20898b8649"

  strings:
    $s1 = "jvirtualization, see the Additional Terms." fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}