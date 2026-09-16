rule sig_20161024_45fcca102c2a52f3698104e359f64ea7 {
  meta:
    description = "datamaliciousorder - file 20161024_45fcca102c2a52f3698104e359f64ea7.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "37370843168024962384481a4ad668e51304db16e373630d219401b3df3a070f"

  strings:
    $s1 = "} while (uh0++ < fl);" fullword ascii

  condition:
    uint16(0) == 0x0a0a and
    all of them
}