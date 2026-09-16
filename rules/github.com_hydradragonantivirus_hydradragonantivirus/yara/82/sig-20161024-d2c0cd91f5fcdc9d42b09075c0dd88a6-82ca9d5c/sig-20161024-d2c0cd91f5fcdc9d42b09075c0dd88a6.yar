rule sig_20161024_d2c0cd91f5fcdc9d42b09075c0dd88a6 {
  meta:
    description = "datamaliciousorder - file 20161024_d2c0cd91f5fcdc9d42b09075c0dd88a6.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "b6b7a5163bc482719455e1505c8ed80f7884369899dbe23ef2193ed09239ec26"

  strings:
    $s1 = "} while (os++ < tm);" fullword ascii

  condition:
    uint16(0) == 0x0a0a and
    all of them
}