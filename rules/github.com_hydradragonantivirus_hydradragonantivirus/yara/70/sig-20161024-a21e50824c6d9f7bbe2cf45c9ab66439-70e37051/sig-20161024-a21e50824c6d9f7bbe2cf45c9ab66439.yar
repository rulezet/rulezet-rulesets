rule sig_20161024_a21e50824c6d9f7bbe2cf45c9ab66439 {
  meta:
    description = "datamaliciousorder - file 20161024_a21e50824c6d9f7bbe2cf45c9ab66439.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "d44cec005c11ab84af0b48d32f6030d908d72e2488e0b0a53970ad064f3e5b69"

  strings:
    $s1 = "} while (ej0++ < gx0);" fullword ascii

  condition:
    uint16(0) == 0x0a0a and
    all of them
}