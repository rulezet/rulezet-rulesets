rule Virus_Delself_Gen_Heur_Mint_Hiamoe_20_18_1 {
  meta:
    description = "datamaliciousorder - file Virus.Delself_Gen.Heur.Mint.Hiamoe.20_18_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "0e94072acf6db4c63a1db7638bb8677efd201573d217adf73c23c017b2d4b77a"

  strings:
    $s1 = "Ruby 3.2.2 API Reference.lnk" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}