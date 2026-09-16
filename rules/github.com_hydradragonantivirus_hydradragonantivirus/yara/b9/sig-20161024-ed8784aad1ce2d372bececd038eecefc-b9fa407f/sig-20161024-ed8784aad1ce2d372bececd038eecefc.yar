rule sig_20161024_ed8784aad1ce2d372bececd038eecefc {
  meta:
    description = "datamaliciousorder - file 20161024_ed8784aad1ce2d372bececd038eecefc.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "027e919e91b3e8fbec1e460a90fc9cf7b7a8cc995b4f274acaa6c07e788230af"

  strings:
    $s1 = "} while (eg++ < zz0);" fullword ascii

  condition:
    uint16(0) == 0x0a0a and
    all of them
}