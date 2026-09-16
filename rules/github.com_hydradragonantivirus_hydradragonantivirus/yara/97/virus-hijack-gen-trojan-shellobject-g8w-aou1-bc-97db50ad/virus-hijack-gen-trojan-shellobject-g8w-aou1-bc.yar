rule Virus_Hijack_Gen_Trojan_ShellObject_g8W_aOU1_bc {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Gen.Trojan.ShellObject.g8W@aOU1!bc.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "f02d94547b8609706fbeed3f76dfeda30dc0e3f20efc1d3c8b56d80ca5c41461"

  strings:
    $s1 = "4Computer: is defined as the computer on which the programs are installed. A Computer license allows you to use the" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}