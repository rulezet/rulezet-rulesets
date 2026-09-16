rule sig_20161024_61bbfe6431544a2b9ee28d7d75c70ae0 {
  meta:
    description = "datamaliciousorder - file 20161024_61bbfe6431544a2b9ee28d7d75c70ae0.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "05a91424ae45dc91afb647e83a3746fe8e3cdb2986b5dab87082d3bfdd0e7603"

  strings:
    $s1 = "} while (bh++ < gl0);" fullword ascii

  condition:
    uint16(0) == 0x0a0a and
    all of them
}