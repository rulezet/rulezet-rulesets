rule Virus_Hijack_Gen_Trojan_ShellObject_wSZ_a8YIsUn_3 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Gen.Trojan.ShellObject.wSZ@a8YIsUn_3.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "a268c6d1428260ef9bb17d4966dc1381079242e57d5f22c905f6325e735f1914"

  strings:
    $s1 = "agreements or representations, written or oral, regarding such programs and/or service`" fullword ascii
    $s2 = "dremainder of Section B remaining in full force and effect." fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}