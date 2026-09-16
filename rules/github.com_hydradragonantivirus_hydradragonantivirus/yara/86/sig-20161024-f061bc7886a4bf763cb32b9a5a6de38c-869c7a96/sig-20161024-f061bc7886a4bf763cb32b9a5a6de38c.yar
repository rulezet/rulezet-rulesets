rule sig_20161024_f061bc7886a4bf763cb32b9a5a6de38c {
  meta:
    description = "datamaliciousorder - file 20161024_f061bc7886a4bf763cb32b9a5a6de38c.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "bf8ca140dc8a7b1429fb4472bb4053d92566989b3c673a3bc04a6d342945c022"

  strings:
    $s1 = "} while (tr++ < lx);" fullword ascii

  condition:
    uint16(0) == 0x0a0a and
    all of them
}