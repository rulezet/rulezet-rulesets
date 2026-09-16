rule sig_20160823_35e38ff191122d881f91240d8a456963 {
  meta:
    description = "datamaliciousorder - file 20160823_35e38ff191122d881f91240d8a456963.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "0557640bb3b19b0341579f1a4dbc4607be59833d169370a1006c1d3b8aa7cb0b"

  strings:
    $s1 = "var Nt0 = new Array(\"\\x76\",\"\\x61\",\"\\x72\",\"\\x20\",\"\\x5f\",\"\\x77\",\"\\x73\",\"\\x63\",\"\\x69\",\"\\x70\",\"\\x74" ascii

  condition:
    uint16(0) == 0x6176 and
    all of them
}