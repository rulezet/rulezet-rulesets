rule sig_20160823_5acc0e60d20db7b0996322a2d16425cc {
  meta:
    description = "datamaliciousorder - file 20160823_5acc0e60d20db7b0996322a2d16425cc.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "ec61e7ac98987269704a1c3c1d2fdc4d550227882f1781b774fe8995e216fdf4"

  strings:
    $s1 = "var Cp = new Array(\"\\x76\",\"\\x61\",\"\\x72\",\"\\x20\",\"\\x5f\",\"\\x77\",\"\\x73\",\"\\x63\",\"\\x69\",\"\\x70\",\"\\x74\"" ascii

  condition:
    uint16(0) == 0x6176 and
    all of them
}