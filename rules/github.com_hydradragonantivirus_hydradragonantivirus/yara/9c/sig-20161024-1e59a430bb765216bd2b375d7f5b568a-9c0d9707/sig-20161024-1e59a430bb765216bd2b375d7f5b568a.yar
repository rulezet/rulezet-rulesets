rule sig_20161024_1e59a430bb765216bd2b375d7f5b568a {
  meta:
    description = "datamaliciousorder - file 20161024_1e59a430bb765216bd2b375d7f5b568a.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "d9af836ef3a6d56d7bad09c6c424461cdc9e98ce1861195b7f046923c075b426"

  strings:
    $s1 = "} while (ek++ < cc);" fullword ascii

  condition:
    uint16(0) == 0x0a0a and
    all of them
}