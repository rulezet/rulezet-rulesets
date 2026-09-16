rule sig_20161024_a00d51ad01dd9f0d0094ac00b9b0422a {
  meta:
    description = "datamaliciousorder - file 20161024_a00d51ad01dd9f0d0094ac00b9b0422a.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "6f829cf43654bdc577369bf5e0aa8b2ccc5b52f2f21f549ec321a4a5ad789109"

  strings:
    $s1 = "} while (vi++ < rm);" fullword ascii

  condition:
    uint16(0) == 0x0a0a and
    all of them
}