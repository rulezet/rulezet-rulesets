rule Virus_Hijack_Gen_Trojan_ShellObject_dCW_aGhujNi_53 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Gen.Trojan.ShellObject.dCW@aGhujNi_53.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "4c2ef8559adf9c9ad5e6dbca25c209090cbe9a10d2809c852403917fd88d0bee"

  strings:
    $s1 = "^$Joky" fullword ascii
    $s2 = "^ Joky" fullword ascii
    $s3 = "^,Joky" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}