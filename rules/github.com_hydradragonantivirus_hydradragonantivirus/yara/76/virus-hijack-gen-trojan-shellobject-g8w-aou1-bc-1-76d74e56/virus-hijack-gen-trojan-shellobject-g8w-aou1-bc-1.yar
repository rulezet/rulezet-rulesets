rule Virus_Hijack_Gen_Trojan_ShellObject_g8W_aOU1_bc_1 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Gen.Trojan.ShellObject.g8W@aOU1!bc_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "d9185b8a0abb517bd220f4ba072bf03a4f2443be73f002ff358ada189a0c4c74"

  strings:
    $s1 = "VComputer: is defined as the computer on which the programs are installed. A Computer license allows you to use the" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}