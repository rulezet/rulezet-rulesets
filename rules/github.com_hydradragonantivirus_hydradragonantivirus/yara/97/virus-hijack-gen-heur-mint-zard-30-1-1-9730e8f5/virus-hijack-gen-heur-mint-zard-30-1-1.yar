rule Virus_Hijack_Gen_Heur_Mint_Zard_30_1_1 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Gen.Heur.Mint.Zard.30_1_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "d6a78cd068639497f3407e021df696fc15daf316d24526ff22de2ae6745ef7fd"

  strings:
    $s1 = "kingsoft antivirus mail monitor proxy" fullword ascii
    $s2 = "Mail From:<" fullword ascii
    $s3 = "Subject: =?gb2312?B?" fullword ascii
    $s4 = "aseM*x" fullword ascii
    $s5 = "  Socket" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}