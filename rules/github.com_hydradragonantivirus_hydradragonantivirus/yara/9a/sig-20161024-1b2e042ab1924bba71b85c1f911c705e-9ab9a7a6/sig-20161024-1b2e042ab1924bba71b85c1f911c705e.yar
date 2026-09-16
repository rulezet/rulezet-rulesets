rule sig_20161024_1b2e042ab1924bba71b85c1f911c705e {
  meta:
    description = "datamaliciousorder - file 20161024_1b2e042ab1924bba71b85c1f911c705e.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "81b4857a173f980dce6f8c8ab3151b01f8f06439093608573dbc58fe011d0b83"

  strings:
    $s1 = "} while (jn++ < nh);" fullword ascii

  condition:
    uint16(0) == 0x0a0a and
    all of them
}