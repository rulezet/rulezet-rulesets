rule sig_20161024_f0eb2d922e0564b01a24461bfff3d67b {
  meta:
    description = "datamaliciousorder - file 20161024_f0eb2d922e0564b01a24461bfff3d67b.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "df90a6136255d39caa13d11e21d5e632cff31e55073f2e5516f3cec72996d206"

  strings:
    $s1 = "} while (in0++ < fl);" fullword ascii

  condition:
    uint16(0) == 0x0a0a and
    all of them
}