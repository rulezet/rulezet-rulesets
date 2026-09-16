rule sig_20161024_ac79132a357af8bf82bfe1d7cf2ba848 {
  meta:
    description = "datamaliciousorder - file 20161024_ac79132a357af8bf82bfe1d7cf2ba848.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "601584fdcfb36b267353b85d040979b45c744660e4df5c0794f6be53c43ee0a7"

  strings:
    $s1 = "} while (sd0++ < ib);" fullword ascii

  condition:
    uint16(0) == 0x0a0a and
    all of them
}