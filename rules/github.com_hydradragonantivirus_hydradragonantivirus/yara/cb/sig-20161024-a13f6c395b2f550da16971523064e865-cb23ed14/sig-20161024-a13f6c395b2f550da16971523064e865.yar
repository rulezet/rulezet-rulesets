rule sig_20161024_a13f6c395b2f550da16971523064e865 {
  meta:
    description = "datamaliciousorder - file 20161024_a13f6c395b2f550da16971523064e865.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "14acf8a7565dedbb6bc867540face50a4ced56853d82ea48aa9be7cd1b5583f9"

  strings:
    $s1 = "} while (je++ < ib);" fullword ascii

  condition:
    uint16(0) == 0x0a0a and
    all of them
}