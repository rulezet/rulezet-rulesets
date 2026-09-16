rule sig_20161024_171d761e2cea42056c015700162c9c31 {
  meta:
    description = "datamaliciousorder - file 20161024_171d761e2cea42056c015700162c9c31.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "3107c55fb3533d2666fe04883d8754fe31181e67444698b9e64881a499c36278"

  strings:
    $s1 = "} while (uf0++ < fk);" fullword ascii

  condition:
    uint16(0) == 0x0a0a and
    all of them
}