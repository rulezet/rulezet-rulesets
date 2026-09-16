rule sig_20161024_4eedce394dc43b405aec2664a626078f {
  meta:
    description = "datamaliciousorder - file 20161024_4eedce394dc43b405aec2664a626078f.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "a3565e562565d518eae6721bae1b1e22fcf6239ae75ab149762971e1a5d485bf"

  strings:
    $s1 = "} while (zr1++ < ie);" fullword ascii

  condition:
    uint16(0) == 0x0a0a and
    all of them
}