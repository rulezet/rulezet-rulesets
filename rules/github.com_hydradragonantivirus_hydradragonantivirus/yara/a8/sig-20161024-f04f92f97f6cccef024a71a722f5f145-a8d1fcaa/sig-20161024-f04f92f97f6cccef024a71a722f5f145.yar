rule sig_20161024_f04f92f97f6cccef024a71a722f5f145 {
  meta:
    description = "datamaliciousorder - file 20161024_f04f92f97f6cccef024a71a722f5f145.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "3a157596bd516555bd76bbe6ceb86b7b80630813108efcf0582fa99e12be9724"

  strings:
    $s1 = "} while (wf++ < gv);" fullword ascii

  condition:
    uint16(0) == 0x0a0a and
    all of them
}