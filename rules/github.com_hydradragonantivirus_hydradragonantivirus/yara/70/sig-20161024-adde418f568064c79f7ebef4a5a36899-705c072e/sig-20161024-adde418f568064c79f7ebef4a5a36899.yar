rule sig_20161024_adde418f568064c79f7ebef4a5a36899 {
  meta:
    description = "datamaliciousorder - file 20161024_adde418f568064c79f7ebef4a5a36899.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "2c162d9f815a15107ab4b95910253b27cf4dd3ce279d4150a2feddd238b8ffda"

  strings:
    $s1 = "} while (mm++ < ge);" fullword ascii

  condition:
    uint16(0) == 0x0a0a and
    all of them
}