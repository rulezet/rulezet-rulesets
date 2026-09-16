rule Virus_Hooker_Gen_Trojan_UserStartup_4iZ_aODEVdp_1 {
  meta:
    description = "datamaliciousorder - file Virus.Hooker_Gen.Trojan.UserStartup.4iZ@aODEVdp_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "664ad7f7cfb79d513d888d27006b765dc25eb80cd1fa8036fd060005b19510da"

  strings:
    $s1 = "&N`kiRI" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}