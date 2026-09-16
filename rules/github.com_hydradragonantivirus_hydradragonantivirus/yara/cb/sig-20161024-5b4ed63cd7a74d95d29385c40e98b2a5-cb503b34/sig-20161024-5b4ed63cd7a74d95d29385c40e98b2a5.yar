rule sig_20161024_5b4ed63cd7a74d95d29385c40e98b2a5 {
  meta:
    description = "datamaliciousorder - file 20161024_5b4ed63cd7a74d95d29385c40e98b2a5.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "85bd9076a7966abc3170072decb75c5b00ec75aa4f2e76cb412bcdb70195de9b"

  strings:
    $s1 = "} while (cp++ < ur);" fullword ascii

  condition:
    uint16(0) == 0x0a0a and
    all of them
}