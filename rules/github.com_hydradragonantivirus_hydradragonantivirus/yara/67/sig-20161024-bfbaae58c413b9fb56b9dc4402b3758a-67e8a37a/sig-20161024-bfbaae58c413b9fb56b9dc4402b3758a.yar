rule sig_20161024_bfbaae58c413b9fb56b9dc4402b3758a {
  meta:
    description = "datamaliciousorder - file 20161024_bfbaae58c413b9fb56b9dc4402b3758a.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "e4fe11afcf5a63f8cebbbc508b7391d327f26f2a7542864930af4e271b3f6f5d"

  strings:
    $s1 = "} while (wr++ < yr);" fullword ascii

  condition:
    uint16(0) == 0x0a0a and
    all of them
}