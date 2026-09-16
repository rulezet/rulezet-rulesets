rule Virus_Autorun_Worm_FakeDoc_14 {
  meta:
    description = "datamaliciousorder - file Virus.Autorun_Worm.FakeDoc_14.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "97e9f36d0b649759be5523c1107370f1385831647f8c58ccc7d15edee03b56b1"

  strings:
    $s1 = "<</Type/Catalog/Pages 2 0 R/Lang(ru-RU) /StructTreeRoot 28 0 R/MarkInfo<</Marked true>>>>" fullword ascii
    $s2 = "Width 2665/FontWeight 400/XHeight 250/Leading 33/StemV 44/FontBBox[ -665 -210 2000 728] /FontFile2 267 0 R>>" fullword ascii
    $s3 = "rent 4>>" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}