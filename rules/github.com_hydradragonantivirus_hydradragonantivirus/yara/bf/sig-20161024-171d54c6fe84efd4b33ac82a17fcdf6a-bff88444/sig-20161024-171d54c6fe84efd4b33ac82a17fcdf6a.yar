rule sig_20161024_171d54c6fe84efd4b33ac82a17fcdf6a {
  meta:
    description = "datamaliciousorder - file 20161024_171d54c6fe84efd4b33ac82a17fcdf6a.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "8b5aa66586abeb495233f3083140fb53d589c3c0a2ef590981d3fa9c76e0bd8c"

  strings:
    $s1 = "} while (xy++ < hk);" fullword ascii

  condition:
    uint16(0) == 0x0a0a and
    all of them
}