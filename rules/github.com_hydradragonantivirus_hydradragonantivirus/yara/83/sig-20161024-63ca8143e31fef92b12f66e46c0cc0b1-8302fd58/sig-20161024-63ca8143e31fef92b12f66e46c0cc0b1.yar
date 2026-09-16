rule sig_20161024_63ca8143e31fef92b12f66e46c0cc0b1 {
  meta:
    description = "datamaliciousorder - file 20161024_63ca8143e31fef92b12f66e46c0cc0b1.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "51e7012f84e9360375e3d802e251e9146504de4b1cbf0fb1d9f7a8310b1553cf"

  strings:
    $s1 = "} while (oe++ < ec);" fullword ascii

  condition:
    uint16(0) == 0x0a0a and
    all of them
}