rule sig_20161024_d335bb5f058093398d56e895e497063b {
  meta:
    description = "datamaliciousorder - file 20161024_d335bb5f058093398d56e895e497063b.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "fbce2b7e797543b55cf80c8f060139a4320dbe6a31c1a3cb799da5ba12afcf92"

  strings:
    $s1 = "} while (wl0++ < rf);" fullword ascii

  condition:
    uint16(0) == 0x0a0a and
    all of them
}