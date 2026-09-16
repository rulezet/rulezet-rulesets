rule sig_20161024_bf2f258e5491119f120605f00e79a927 {
  meta:
    description = "datamaliciousorder - file 20161024_bf2f258e5491119f120605f00e79a927.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "fa2718974cbabc60f83577ba232a6802752c24461ed820544c9aa266320fa013"

  strings:
    $s1 = "} while (iw++ < ta);" fullword ascii

  condition:
    uint16(0) == 0x0a0a and
    all of them
}