rule sig_20161024_0c0cc5acf6c3309db11ad2476cb84a31 {
  meta:
    description = "datamaliciousorder - file 20161024_0c0cc5acf6c3309db11ad2476cb84a31.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "dba9f68142db14568df9b079f764b5321b9a0e0528130e40eaa577bbcb17d5dd"

  strings:
    $s1 = "} while (ep++ < nr);" fullword ascii

  condition:
    uint16(0) == 0x0a0a and
    all of them
}