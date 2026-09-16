rule Worm__Gen_Variant_Downloader_126_1 {
  meta:
    description = "datamaliciousorder - file Worm _Gen.Variant.Downloader.126_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "60736642b3c21361fb3aab74bd57a05a2f1f13f5b19fb7c970466bddafd4925f"

  strings:
    $s1 = "WRP Integrity API" fullword wide

  condition:
    uint16(0) == 0x5a4d and
    all of them
}