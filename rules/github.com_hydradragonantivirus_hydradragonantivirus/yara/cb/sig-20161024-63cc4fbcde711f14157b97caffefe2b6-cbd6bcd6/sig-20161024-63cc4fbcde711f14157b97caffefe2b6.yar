rule sig_20161024_63cc4fbcde711f14157b97caffefe2b6 {
  meta:
    description = "datamaliciousorder - file 20161024_63cc4fbcde711f14157b97caffefe2b6.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "aa487c4bf0c0c45f15ed7cd2a793b0897c7842e41a6310f130a17c7f26e07351"

  strings:
    $s1 = "} while (eo++ < vv);" fullword ascii

  condition:
    uint16(0) == 0x0a0a and
    all of them
}