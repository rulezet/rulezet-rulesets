rule sig_20160823_53d9c9c5008fdb374d9477d41298fe57 {
  meta:
    description = "datamaliciousorder - file 20160823_53d9c9c5008fdb374d9477d41298fe57.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "89d528f2d591afa8eabdead30dc3f87f110606141b449ff662b87aff2c27cae8"

  strings:
    $s1 = "var Ha8 = new Array(\"\\x76\",\"\\x61\",\"\\x72\",\"\\x20\",\"\\x5f\",\"\\x77\",\"\\x73\",\"\\x63\",\"\\x69\",\"\\x70\",\"\\x74" ascii

  condition:
    uint16(0) == 0x6176 and
    all of them
}