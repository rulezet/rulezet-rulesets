rule Virus_Hijack_Gen_Trojan_ShellObject_g8W_ay4DNrk_5_2 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Gen.Trojan.ShellObject.g8W@ay4DNrk_5_2.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "58365a45c38ca8b3d92acb812f4878e6441ad0100bce05e368d0062b49676952"

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