rule sig_20161024_5152367bc3b5982abc6b342e854c3fc4 {
  meta:
    description = "datamaliciousorder - file 20161024_5152367bc3b5982abc6b342e854c3fc4.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "4c5de726f2be33f3636545c699a070ca617ee1ab369ec623635f3e4f9287a342"

  strings:
    $s1 = "} while (zl++ < bm);" fullword ascii

  condition:
    uint16(0) == 0x0a0a and
    all of them
}