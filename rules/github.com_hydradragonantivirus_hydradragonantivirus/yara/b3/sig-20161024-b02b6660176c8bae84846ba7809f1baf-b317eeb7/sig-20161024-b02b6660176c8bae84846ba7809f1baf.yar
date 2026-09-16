rule sig_20161024_b02b6660176c8bae84846ba7809f1baf {
  meta:
    description = "datamaliciousorder - file 20161024_b02b6660176c8bae84846ba7809f1baf.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "8fa02d97cf0f5382055633455a8d8d8642ab51c7c16c79f15a8b52ae39533c73"

  strings:
    $s1 = "} while (fh++ < wl);" fullword ascii

  condition:
    uint16(0) == 0x0a0a and
    all of them
}