rule sig_20161024_652b3939e6e903808613759da24c3a62 {
  meta:
    description = "datamaliciousorder - file 20161024_652b3939e6e903808613759da24c3a62.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "021c040e65e0b82f09d46ad3cd1af4a4d2acc7b8d2ccd1cda6b1df15875d228b"

  strings:
    $s1 = "} while (rv++ < qy);" fullword ascii

  condition:
    uint16(0) == 0x0a0a and
    all of them
}