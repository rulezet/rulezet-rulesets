rule sig_20160822_7a187f3b2f3522de546c401f96fe76f8 {
  meta:
    description = "datamaliciousorder - file 20160822_7a187f3b2f3522de546c401f96fe76f8.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "57ec4e3ea2c6914a99cc72219ec92c3f0c845888f74dbd949c94c800f9191bfc"

  strings:
    $s1 = "var UGc3 = new Array(\"\\x76\",\"\\x61\",\"\\x72\",\"\\x20\",\"\\x5f\",\"\\x77\",\"\\x73\",\"\\x63\",\"\\x69\",\"\\x70\",\"\\x74" ascii

  condition:
    uint16(0) == 0x6176 and
    all of them
}