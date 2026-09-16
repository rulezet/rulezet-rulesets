rule sig_20161024_c60ff7a1b5796d7ee38545fce9d19ab6 {
  meta:
    description = "datamaliciousorder - file 20161024_c60ff7a1b5796d7ee38545fce9d19ab6.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "2b7414e608a7933e6dedaceb32383f5496326474184b6276b7998d244d4b349d"

  strings:
    $s1 = "} while (gj++ < fw0);" fullword ascii

  condition:
    uint16(0) == 0x0a0a and
    all of them
}