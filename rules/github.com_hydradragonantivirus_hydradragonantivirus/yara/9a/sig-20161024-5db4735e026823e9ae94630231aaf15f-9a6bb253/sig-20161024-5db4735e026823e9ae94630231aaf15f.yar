rule sig_20161024_5db4735e026823e9ae94630231aaf15f {
  meta:
    description = "datamaliciousorder - file 20161024_5db4735e026823e9ae94630231aaf15f.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "d728edfe172ece5b46ef3a9cbaf6e8d99e18ca6392cde48d15263b58a825ae68"

  strings:
    $s1 = "} while (rq++ < sr);" fullword ascii

  condition:
    uint16(0) == 0x0a0a and
    all of them
}