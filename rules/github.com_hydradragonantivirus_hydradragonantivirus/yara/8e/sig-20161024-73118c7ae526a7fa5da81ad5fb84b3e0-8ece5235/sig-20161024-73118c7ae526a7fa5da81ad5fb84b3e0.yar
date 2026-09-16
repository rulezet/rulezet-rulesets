rule sig_20161024_73118c7ae526a7fa5da81ad5fb84b3e0 {
  meta:
    description = "datamaliciousorder - file 20161024_73118c7ae526a7fa5da81ad5fb84b3e0.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "219e5763da02b34eac4d7677e410f6ab11d5d4da5cdcab664098df055e2497af"

  strings:
    $s1 = "} while (wl++ < jn);" fullword ascii

  condition:
    uint16(0) == 0x0a0a and
    all of them
}