rule sig_20161024_eba8a40d8b6704fcb32d57daeabc0a79 {
  meta:
    description = "datamaliciousorder - file 20161024_eba8a40d8b6704fcb32d57daeabc0a79.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "e39e2af33fce67ad78a3fb7ecb1e3c50ae322cbcdb0186ceb9b30153271e1210"

  strings:
    $s1 = "} while (wt++ < ox);" fullword ascii

  condition:
    uint16(0) == 0x0a0a and
    all of them
}