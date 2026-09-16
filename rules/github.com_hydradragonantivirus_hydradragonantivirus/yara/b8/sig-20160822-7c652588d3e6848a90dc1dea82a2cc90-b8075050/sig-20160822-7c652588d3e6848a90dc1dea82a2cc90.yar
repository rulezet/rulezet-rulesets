rule sig_20160822_7c652588d3e6848a90dc1dea82a2cc90 {
  meta:
    description = "datamaliciousorder - file 20160822_7c652588d3e6848a90dc1dea82a2cc90.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "25b11dcf2008d1b968877e47952111ac1941ba3d7c42748ea600db9114fd3545"

  strings:
    $s1 = "var Cp = new Array(\"\\x76\",\"\\x61\",\"\\x72\",\"\\x20\",\"\\x5f\",\"\\x77\",\"\\x73\",\"\\x63\",\"\\x69\",\"\\x70\",\"\\x74\"" ascii

  condition:
    uint16(0) == 0x6176 and
    all of them
}