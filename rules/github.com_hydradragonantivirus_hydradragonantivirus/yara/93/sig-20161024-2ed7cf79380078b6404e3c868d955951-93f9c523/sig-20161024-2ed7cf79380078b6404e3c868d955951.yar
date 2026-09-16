rule sig_20161024_2ed7cf79380078b6404e3c868d955951 {
  meta:
    description = "datamaliciousorder - file 20161024_2ed7cf79380078b6404e3c868d955951.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "f48f018ee41ad9e6f17d71f493776e26cf64d90916a817d7d991abdc95adb5a4"

  strings:
    $s1 = "} while (be++ < le);" fullword ascii

  condition:
    uint16(0) == 0x0a0a and
    all of them
}