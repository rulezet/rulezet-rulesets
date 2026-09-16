rule sig_20161006_5441dc01f13ec29b9a98d3af0f50a785 {
  meta:
    description = "datamaliciousorder - file 20161006_5441dc01f13ec29b9a98d3af0f50a785.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "2835b1790e5dcb68ed555fe313fb9cdddf231847102e614b44cba367c6c3f5f9"

  strings:
    $s1 = "} while (dl++ < ow);" fullword ascii

  condition:
    uint16(0) == 0x2f0a and
    all of them
}