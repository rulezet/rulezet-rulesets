rule Virus_Hijack_Gen_Trojan_ShellObject_g8W_aOU1_bc_11 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Gen.Trojan.ShellObject.g8W@aOU1!bc_11.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "609f1145bbef90230093fe748399d01ae0e216e9f545946652d759371e161675"

  strings:
    $s1 = "q8Computer: is defined as the computer on which the programs are installed. A Computer license allows you to use the" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}