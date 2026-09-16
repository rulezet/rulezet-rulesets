rule Trojan_Autorun_Gen_Heur_Mint_Murphy_3_316_1 {
  meta:
    description = "datamaliciousorder - file Trojan.Autorun_Gen.Heur.Mint.Murphy.3_316_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "f50ee8ea342cb1cfec26c7e80263513052f336207980cbb3e299f1c2ccb815ce"

  strings:
    $s1 = "3hundred euros) in all purchase orders transacted" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}