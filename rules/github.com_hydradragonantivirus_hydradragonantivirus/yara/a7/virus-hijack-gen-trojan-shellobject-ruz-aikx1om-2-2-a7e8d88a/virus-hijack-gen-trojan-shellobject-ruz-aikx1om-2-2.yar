rule Virus_Hijack_Gen_Trojan_ShellObject_ruZ_aikx1Om_2_2 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Gen.Trojan.ShellObject.ruZ@aikx1Om_2_2.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "64b734d16fbb4494c9416c1c9b689583ca9436e5b26e1077e418250e15cf6bd5"

  strings:
    $s1 = "This Setup was created with an EVALUATION VERSION of InstallShield DevStudio" fullword ascii
    $s2 = "Dieses Setup wurde mit einer EVALUATIONSVERSION von InstallShield DevStudio erstellt" fullword ascii
    $s3 = "Copyright (C) 2003 InstallShield Software Corp." fullword wide
    $s4 = "Research and Development1+0)" fullword ascii
    $s5 = "InstallShield Setup Player 2K2" fullword wide

  condition:
    uint16(0) == 0x5a4d and
    all of them
}