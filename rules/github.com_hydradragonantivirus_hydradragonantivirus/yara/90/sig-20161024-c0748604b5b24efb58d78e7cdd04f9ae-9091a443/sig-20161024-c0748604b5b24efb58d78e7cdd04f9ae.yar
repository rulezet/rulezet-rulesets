rule sig_20161024_c0748604b5b24efb58d78e7cdd04f9ae {
  meta:
    description = "datamaliciousorder - file 20161024_c0748604b5b24efb58d78e7cdd04f9ae.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "a97ba760da3f12126155f76144d27adef8d2af79eb9385567e30a9208e27e355"

  strings:
    $s1 = "} while (wr++ < tj);" fullword ascii

  condition:
    uint16(0) == 0x0a0a and
    all of them
}