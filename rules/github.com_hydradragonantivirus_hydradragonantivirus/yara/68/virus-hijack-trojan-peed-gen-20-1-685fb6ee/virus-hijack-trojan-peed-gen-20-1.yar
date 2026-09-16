rule Virus_Hijack_Trojan_Peed_Gen_20_1 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Trojan.Peed.Gen_20_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "3bbc160f4ec68a7fc87b86738f53cdba3f11a2b2b1e07cd90fbcf15464506689"

  strings:
    $s1 = "mINE)QP)" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}