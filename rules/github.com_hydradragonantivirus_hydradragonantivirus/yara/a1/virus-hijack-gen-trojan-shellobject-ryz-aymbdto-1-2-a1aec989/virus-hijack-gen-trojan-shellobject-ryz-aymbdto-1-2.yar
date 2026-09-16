rule Virus_Hijack_Gen_Trojan_ShellObject_ryZ_ayMBdto_1_2 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Gen.Trojan.ShellObject.ryZ@ayMBdto_1_2.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "98629af8f1f4ff73d04dceb2dd335125320a85c04ba2ba3ca5cf2849eabcc320"

  strings:
    $s1 = "$Id: UPX 1.04 Copyright (C) 1996-2000 the UPX Team. All Rights Reserved. $" fullword ascii
    $s2 = "p@gram" fullword ascii
    $s3 = "smash@" fullword ascii
    $s4 = ">>Itch%" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}