rule sig_20160822_69ac2266540da7118dbeb122c1bdfb07 {
  meta:
    description = "datamaliciousorder - file 20160822_69ac2266540da7118dbeb122c1bdfb07.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "72d02878a5c6526a5bff628c9bac6578a4658063309486c7fb48ad66dad49e62"

  strings:
    $s1 = "var Cp = new Array(\"\\x76\",\"\\x61\",\"\\x72\",\"\\x20\",\"\\x5f\",\"\\x77\",\"\\x73\",\"\\x63\",\"\\x69\",\"\\x70\",\"\\x74\"" ascii

  condition:
    uint16(0) == 0x6176 and
    all of them
}