rule sig_20161024_0c761a2358cf636256f82077361c0fcf {
  meta:
    description = "datamaliciousorder - file 20161024_0c761a2358cf636256f82077361c0fcf.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "2bfe01311d97b913b4e6cfdd8e036a365f1e69a6352f0f17c8087b40f88ac272"

  strings:
    $s1 = "} while (hw++ < ey0);" fullword ascii

  condition:
    uint16(0) == 0x0a0a and
    all of them
}