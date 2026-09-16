rule sig_20160822_1d27aed014bcb007c65ab42b728e8029 {
  meta:
    description = "datamaliciousorder - file 20160822_1d27aed014bcb007c65ab42b728e8029.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "d88f39501b27184c091f2b7e9561f6b87c3fa7a009c5f39a95b571abc8664cad"

  strings:
    $s1 = "var UGc3 = new Array(\"\\x76\",\"\\x61\",\"\\x72\",\"\\x20\",\"\\x5f\",\"\\x77\",\"\\x73\",\"\\x63\",\"\\x69\",\"\\x70\",\"\\x74" ascii

  condition:
    uint16(0) == 0x6176 and
    all of them
}