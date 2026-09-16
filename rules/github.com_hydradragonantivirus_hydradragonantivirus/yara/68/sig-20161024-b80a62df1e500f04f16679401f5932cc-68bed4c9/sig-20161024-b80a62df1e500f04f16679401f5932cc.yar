rule sig_20161024_b80a62df1e500f04f16679401f5932cc {
  meta:
    description = "datamaliciousorder - file 20161024_b80a62df1e500f04f16679401f5932cc.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "2cdbdf8c6dd44c1dc4965b349107b096fae895415cc950179c15e8cb8b7ef8ae"

  strings:
    $s1 = "} while (fy++ < re);" fullword ascii

  condition:
    uint16(0) == 0x0a0a and
    all of them
}