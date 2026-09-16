rule sig_20161024_33f6bd2dae522662321ff8c807e35ba8 {
  meta:
    description = "datamaliciousorder - file 20161024_33f6bd2dae522662321ff8c807e35ba8.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "adcab970360c89f9924a29f865694fe416df1e7c7ca8d6db4398f74cb1c20edc"

  strings:
    $s1 = "} while (xw++ < fq);" fullword ascii

  condition:
    uint16(0) == 0x0a0a and
    all of them
}