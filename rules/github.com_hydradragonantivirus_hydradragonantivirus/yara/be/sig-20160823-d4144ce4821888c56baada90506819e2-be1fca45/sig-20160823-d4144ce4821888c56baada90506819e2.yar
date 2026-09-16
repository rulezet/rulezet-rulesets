rule sig_20160823_d4144ce4821888c56baada90506819e2 {
  meta:
    description = "datamaliciousorder - file 20160823_d4144ce4821888c56baada90506819e2.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "ceedc324215f68d4025c968dd0f9e85be841643cd6ab7aaecf93a0a84b087a99"

  strings:
    $s1 = "var Nt0 = new Array(\"\\x76\",\"\\x61\",\"\\x72\",\"\\x20\",\"\\x5f\",\"\\x77\",\"\\x73\",\"\\x63\",\"\\x69\",\"\\x70\",\"\\x74" ascii

  condition:
    uint16(0) == 0x6176 and
    all of them
}