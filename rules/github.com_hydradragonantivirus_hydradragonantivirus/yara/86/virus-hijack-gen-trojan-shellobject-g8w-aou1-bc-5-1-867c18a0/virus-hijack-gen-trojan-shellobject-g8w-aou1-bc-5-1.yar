rule Virus_Hijack_Gen_Trojan_ShellObject_g8W_aOU1_bc_5_1 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Gen.Trojan.ShellObject.g8W@aOU1!bc_5_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "eac8c07d08dd5e4598473f5f40ea65b3ea40b0d12b2e0100d7db3d5023301a35"

  strings:
    $s1 = "forerun" fullword ascii
    $s2 = "[Not compatible with your windows version]" fullword wide
    $s3 = "Error Syst32" fullword wide

  condition:
    uint16(0) == 0x5a4d and
    all of them
}