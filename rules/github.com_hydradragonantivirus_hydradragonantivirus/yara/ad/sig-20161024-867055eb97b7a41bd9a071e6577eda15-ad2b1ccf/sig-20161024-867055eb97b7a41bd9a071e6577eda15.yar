rule sig_20161024_867055eb97b7a41bd9a071e6577eda15 {
  meta:
    description = "datamaliciousorder - file 20161024_867055eb97b7a41bd9a071e6577eda15.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "b22021f5e743b284e3fb8bce957bfc6834117de9cb03653decae5ed176d87244"

  strings:
    $s1 = "} while (al++ < lu);" fullword ascii

  condition:
    uint16(0) == 0x0a0a and
    all of them
}