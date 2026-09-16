rule Trojan_Danger_Gen_Variant_Ransom_Xpiro_2_200 {
  meta:
    description = "datamaliciousorder - file Trojan.Danger_Gen.Variant.Ransom.Xpiro.2_200.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "f649a70fd4216368578e2e930a06ba08ab2bfad9fe0030a75507239a800b5569"

  strings:
    $s1 = "#AutoIt Window Info (x64).lnk" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}