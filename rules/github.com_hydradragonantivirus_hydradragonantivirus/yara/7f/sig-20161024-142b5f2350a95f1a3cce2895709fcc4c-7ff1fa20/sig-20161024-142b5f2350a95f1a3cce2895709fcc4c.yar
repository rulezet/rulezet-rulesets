rule sig_20161024_142b5f2350a95f1a3cce2895709fcc4c {
  meta:
    description = "datamaliciousorder - file 20161024_142b5f2350a95f1a3cce2895709fcc4c.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "07a7a3f20ec1894892a4da507b4bca0836c85309e8a2a659188a80eeb3eeaf1d"

  strings:
    $s1 = "} while (ib++ < yk);" fullword ascii

  condition:
    uint16(0) == 0x0a0a and
    all of them
}