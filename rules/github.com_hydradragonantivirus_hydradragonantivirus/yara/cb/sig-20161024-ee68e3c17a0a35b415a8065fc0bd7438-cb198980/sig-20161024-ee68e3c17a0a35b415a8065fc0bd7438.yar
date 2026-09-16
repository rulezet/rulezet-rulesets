rule sig_20161024_ee68e3c17a0a35b415a8065fc0bd7438 {
  meta:
    description = "datamaliciousorder - file 20161024_ee68e3c17a0a35b415a8065fc0bd7438.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "cf3dc63954de130254c4eea1d593801546b0f50764cda306fcf30cc04e3351b8"

  strings:
    $s1 = "} while (yt++ < yk);" fullword ascii

  condition:
    uint16(0) == 0x0a0a and
    all of them
}