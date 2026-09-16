rule Virus_Hooker_Gen_Trojan_UserStartup_hiZ_aODEVdp_1 {
  meta:
    description = "datamaliciousorder - file Virus.Hooker_Gen.Trojan.UserStartup.hiZ@aODEVdp_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "892a77ab0feda4eb4a8630d89d2e5fd749b1b066289ae45c6e4292b9ab0c9546"

  strings:
    $s1 = "B&nOUn" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}