rule sig_20161024_de824dd53c2f01a184933e40150c4458 {
  meta:
    description = "datamaliciousorder - file 20161024_de824dd53c2f01a184933e40150c4458.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "8d4c795e6f7775af4412779182cafb25d645844a3d439236889bf5368d318e47"

  strings:
    $s1 = "} while (km++ < kh);" fullword ascii

  condition:
    uint16(0) == 0x0a0a and
    all of them
}