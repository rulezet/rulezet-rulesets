rule sig_20161024_72960b06a840e00e90b8b07a64cfd89d {
  meta:
    description = "datamaliciousorder - file 20161024_72960b06a840e00e90b8b07a64cfd89d.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "0ffc6f77a2e69325958b8a9b2f7c2096d6a6ab03f9423407912ff081d17bced7"

  strings:
    $s1 = "} while (os++ < nm);" fullword ascii

  condition:
    uint16(0) == 0x0a0a and
    all of them
}