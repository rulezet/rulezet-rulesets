rule sig_20161024_6e2e2a5f2d92c9e02c15b69350d9cb16 {
  meta:
    description = "datamaliciousorder - file 20161024_6e2e2a5f2d92c9e02c15b69350d9cb16.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "9acfa796f8bde02f480acf2d56b2b1c27a1ea8844e59cdadb4119facd85a3f88"

  strings:
    $s1 = "} while (xn++ < mx);" fullword ascii

  condition:
    uint16(0) == 0x0a0a and
    all of them
}