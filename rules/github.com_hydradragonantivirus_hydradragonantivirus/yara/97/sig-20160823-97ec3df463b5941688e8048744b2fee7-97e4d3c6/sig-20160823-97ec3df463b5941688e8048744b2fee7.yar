rule sig_20160823_97ec3df463b5941688e8048744b2fee7 {
  meta:
    description = "datamaliciousorder - file 20160823_97ec3df463b5941688e8048744b2fee7.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "2757dde5d888fbbd0bf6084c9386222f570227a643134b40140487bfbbf71d1d"

  strings:
    $s1 = "var Nt0 = new Array(\"\\x76\",\"\\x61\",\"\\x72\",\"\\x20\",\"\\x5f\",\"\\x77\",\"\\x73\",\"\\x63\",\"\\x69\",\"\\x70\",\"\\x74" ascii

  condition:
    uint16(0) == 0x6176 and
    all of them
}