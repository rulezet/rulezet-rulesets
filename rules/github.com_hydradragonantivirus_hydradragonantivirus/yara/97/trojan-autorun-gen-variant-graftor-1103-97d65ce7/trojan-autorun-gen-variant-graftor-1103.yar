rule Trojan_Autorun_Gen_Variant_Graftor_1103 {
  meta:
    description = "datamaliciousorder - file Trojan.Autorun_Gen.Variant.Graftor.1103.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "5f8cf03fb8d6c13b3404447b27e2cf3ab17d4d05d4f58ae2fed74c143fc69b7b"

  strings:
    $s1 = "7f9e=8>@?nAmE@FHGvIuMHNPO~Q}UPVXW" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}