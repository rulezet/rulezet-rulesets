rule sig_20161024_0cf576ca28f79ba3d6113f294636cca0 {
  meta:
    description = "datamaliciousorder - file 20161024_0cf576ca28f79ba3d6113f294636cca0.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "544a9dc86b932564437afdaba6cdfd0848acf8052e282e19e4b44b59382915be"

  strings:
    $s1 = "} while (iv++ < tx);" fullword ascii

  condition:
    uint16(0) == 0x0a0a and
    all of them
}