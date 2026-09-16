rule sig_20161024_d304cf1212938401fdb5343aebcacf71 {
  meta:
    description = "datamaliciousorder - file 20161024_d304cf1212938401fdb5343aebcacf71.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "bfb39ff993863210abbb15d6154dc572f63b77b6195ec7f35c202cdd191dfe25"

  strings:
    $s1 = "} while (hi++ < yb);" fullword ascii

  condition:
    uint16(0) == 0x0a0a and
    all of them
}