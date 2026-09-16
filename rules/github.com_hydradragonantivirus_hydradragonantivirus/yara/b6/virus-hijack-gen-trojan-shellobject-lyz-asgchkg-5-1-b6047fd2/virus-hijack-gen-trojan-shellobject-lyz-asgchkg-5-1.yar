rule Virus_Hijack_Gen_Trojan_ShellObject_lyZ_aSgChKg_5_1 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Gen.Trojan.ShellObject.lyZ@aSgChKg_5_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "e52463c8219846314d689d7a39616b3e56cbbd35eefd810b7e4423038bb74ae2"

  strings:
    $s1 = "select CommandLine from Win32_Process where Name='{0}'" fullword wide
    $s2 = "/Copyright 2021 Google LLC. All rights reserved." fullword ascii
    $s3 = "MUtT[d" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}