rule sig_20161024_d2a28ba2d852bfffb63400d25df267dd {
  meta:
    description = "datamaliciousorder - file 20161024_d2a28ba2d852bfffb63400d25df267dd.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "22a8e950b692b68e632e14d99b2a6ec7a71ca4c36767eeb9b20ae2e16aeda43b"

  strings:
    $s1 = "} while (il++ < yx);" fullword ascii

  condition:
    uint16(0) == 0x0a0a and
    all of them
}