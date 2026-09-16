rule Virus_Hijack_Gen_Trojan_ShellObject_uGZ_ayM4QWg_21_2 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Gen.Trojan.ShellObject.uGZ@ayM4QWg_21_2.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "161d8b2eeed56c3ba9f9e7a191e86d0fb7302989c9ff3f594bd60397dc09ecab"

  strings:
    $s1 = "Portions Copyright (c) 198" fullword ascii
    $s2 = "Sync!_iz3" fullword ascii
    $s3 = "L FROM:<" fullword ascii
    $s4 = "k/)From" fullword ascii
    $s5 = ">!Aqua" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}