rule Virus_Hijack_Gen_Heur_Emotet_5_3 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Gen.Heur.Emotet.5_3.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "4daecaf06d75fca051b91c9cd9ecee97ac7bbafc2e19b73fe10da702fcc01899"

  strings:
    $s1 = "dropflower" fullword wide
    $s2 = "textilist" fullword wide
    $s3 = "Unbasedness" fullword wide

  condition:
    uint16(0) == 0x5a4d and
    all of them
}