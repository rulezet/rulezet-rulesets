rule Trojan_Autorun_Gen_Heur_Mint_Murphy_3_241_1 {
  meta:
    description = "datamaliciousorder - file Trojan.Autorun_Gen.Heur.Mint.Murphy.3_241_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "1ab0bf898b89b5e8bac48b56e2ffaad2d4cb207e54c02d0f81ba907018b95f3f"

  strings:
    $s1 = "[2013 software. For your convenience, we" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}