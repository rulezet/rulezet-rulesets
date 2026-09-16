rule sig_20161024_10d66593e8f1cf6ee01f3c3bdb401c0c {
  meta:
    description = "datamaliciousorder - file 20161024_10d66593e8f1cf6ee01f3c3bdb401c0c.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "eacc6847309dca04ebbba2382ca03ebbd50f0ff99e3c2d0292a3483db54da378"

  strings:
    $s1 = "} while (rv++ < ns);" fullword ascii

  condition:
    uint16(0) == 0x0a0a and
    all of them
}