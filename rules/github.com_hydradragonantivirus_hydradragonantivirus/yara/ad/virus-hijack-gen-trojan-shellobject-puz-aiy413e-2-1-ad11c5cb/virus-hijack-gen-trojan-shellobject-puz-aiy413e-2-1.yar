rule Virus_Hijack_Gen_Trojan_ShellObject_puZ_aiy413e_2_1 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Gen.Trojan.ShellObject.puZ@aiy413e_2_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "c4cf78e38bd1ccafd75cf6e8c2784904ae19f351c086e7c346ab6767ecc830be"

  strings:
    $s1 = "PAIR:G&r" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}