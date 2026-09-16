rule Virus_Hijack_Gen_Trojan_ShellObject_t8Z_a0kuefc_1 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Gen.Trojan.ShellObject.t8Z@a0kuefc_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "1333760d96fb8f8b8588f74c7674f1d3694ecdab8dc9fd051fc12ccb3655d7f0"

  strings:
    $s1 = "]virtualization, see the Additional Terms." fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}