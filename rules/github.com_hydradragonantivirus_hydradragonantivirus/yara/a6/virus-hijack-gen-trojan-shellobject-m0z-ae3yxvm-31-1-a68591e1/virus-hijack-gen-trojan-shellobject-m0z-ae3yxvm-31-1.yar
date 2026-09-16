rule Virus_Hijack_Gen_Trojan_ShellObject_m0Z_ae3yXvm_31_1 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Gen.Trojan.ShellObject.m0Z@ae3yXvm_31_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "ed5431b66bafb22325ee2ae358812867294803ccc8fd464f0ee0d962dbf3b504"

  strings:
    $s1 = "Darkick Commander" fullword ascii
    $s2 = "Font(TD" fullword ascii
    $s3 = "Color`ND" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}