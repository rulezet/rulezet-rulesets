rule sig_20161024_6abb711acb42c9203439608c0a36ff0d {
  meta:
    description = "datamaliciousorder - file 20161024_6abb711acb42c9203439608c0a36ff0d.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "f61f26c44d2985e0ccd40047a4f57bca8cd75f9e4bec37fed53465141366cdcc"

  strings:
    $s1 = "} while (yx++ < jf);" fullword ascii

  condition:
    uint16(0) == 0x0a0a and
    all of them
}