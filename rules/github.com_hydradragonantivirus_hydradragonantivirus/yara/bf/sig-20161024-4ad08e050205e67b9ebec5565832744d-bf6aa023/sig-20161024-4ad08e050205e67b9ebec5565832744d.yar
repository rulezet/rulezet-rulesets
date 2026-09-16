rule sig_20161024_4ad08e050205e67b9ebec5565832744d {
  meta:
    description = "datamaliciousorder - file 20161024_4ad08e050205e67b9ebec5565832744d.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "088c58e02d8eeaac3718c3b0106929fc8f4c9db646263c944f58c22f1f756ba1"

  strings:
    $s1 = "} while (ei++ < ew);" fullword ascii

  condition:
    uint16(0) == 0x0a0a and
    all of them
}