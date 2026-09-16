rule sig_20161024_f61c992478b53c4c4c52d09ca2f54bbc {
  meta:
    description = "datamaliciousorder - file 20161024_f61c992478b53c4c4c52d09ca2f54bbc.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "43c34af05340db0cf77c589e8e819382a4a2e912d3a5e5cbc2e16ecb52ccb885"

  strings:
    $s1 = "} while (dm++ < yr);" fullword ascii

  condition:
    uint16(0) == 0x0a0a and
    all of them
}