rule sig_20161024_4bb918369aadd0c44f4ad84334001801 {
  meta:
    description = "datamaliciousorder - file 20161024_4bb918369aadd0c44f4ad84334001801.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "c933a13b0a61c51a30167f19d2255453b462fce5952e81d078002f703f5faf22"

  strings:
    $s1 = "} while (ud++ < ee);" fullword ascii

  condition:
    uint16(0) == 0x0a0a and
    all of them
}