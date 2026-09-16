rule Trojan_Danger_Gen_Variant_Ransom_Xpiro_7_155 {
  meta:
    description = "datamaliciousorder - file Trojan.Danger_Gen.Variant.Ransom.Xpiro.7_155.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "babb880b0985f9a99ce4288cd44b5fe11efc5aa5a657f902512a3083d690bde6"

  strings:
    $s1 = "Microsoft Office OneNote 2007.lnk" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}