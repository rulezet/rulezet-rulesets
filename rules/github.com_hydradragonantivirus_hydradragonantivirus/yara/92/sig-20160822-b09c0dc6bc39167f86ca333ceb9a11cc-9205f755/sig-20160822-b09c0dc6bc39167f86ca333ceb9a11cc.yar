rule sig_20160822_b09c0dc6bc39167f86ca333ceb9a11cc {
  meta:
    description = "datamaliciousorder - file 20160822_b09c0dc6bc39167f86ca333ceb9a11cc.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "1148d0c79f0d83b194a38ba403c6cd9e7db0cfba42d66fc37ca89ee236ceabe0"

  strings:
    $s1 = "var Cp = new Array(\"\\x76\",\"\\x61\",\"\\x72\",\"\\x20\",\"\\x5f\",\"\\x77\",\"\\x73\",\"\\x63\",\"\\x69\",\"\\x70\",\"\\x74\"" ascii

  condition:
    uint16(0) == 0x6176 and
    all of them
}