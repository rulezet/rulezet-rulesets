rule sig_20161024_78941d2b3d8b5f3bd304a87a72c92c4e {
  meta:
    description = "datamaliciousorder - file 20161024_78941d2b3d8b5f3bd304a87a72c92c4e.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "d508ed0edb8aeeaa01d986aa73a27a6fc0722ead86465968dde142d4ebeead4b"

  strings:
    $s1 = "} while (ev++ < lm0);" fullword ascii

  condition:
    uint16(0) == 0x0a0a and
    all of them
}