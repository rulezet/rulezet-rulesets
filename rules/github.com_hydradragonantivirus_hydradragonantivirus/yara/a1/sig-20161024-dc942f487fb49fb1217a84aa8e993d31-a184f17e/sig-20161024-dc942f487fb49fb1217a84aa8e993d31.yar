rule sig_20161024_dc942f487fb49fb1217a84aa8e993d31 {
  meta:
    description = "datamaliciousorder - file 20161024_dc942f487fb49fb1217a84aa8e993d31.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "1b056f49d606fa6d010bd78dc421bb3f4eeb975bc985f1e0a30ee2bf43772a17"

  strings:
    $s1 = "} while (pp++ < nl);" fullword ascii

  condition:
    uint16(0) == 0x0a0a and
    all of them
}