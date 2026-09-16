rule sig_20161024_ed9c20d5b77941e0f3b69f11547c8221 {
  meta:
    description = "datamaliciousorder - file 20161024_ed9c20d5b77941e0f3b69f11547c8221.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "ddbd6c90e5b7c57f8fcc7df23bc0de0a513cf7056e5d7e9f491efecd9066927f"

  strings:
    $s1 = "} while (cp0++ < fe);" fullword ascii

  condition:
    uint16(0) == 0x0a0a and
    all of them
}