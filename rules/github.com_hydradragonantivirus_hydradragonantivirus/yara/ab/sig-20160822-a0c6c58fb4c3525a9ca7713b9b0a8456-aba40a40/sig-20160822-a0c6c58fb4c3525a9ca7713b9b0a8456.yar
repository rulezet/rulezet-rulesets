rule sig_20160822_a0c6c58fb4c3525a9ca7713b9b0a8456 {
  meta:
    description = "datamaliciousorder - file 20160822_a0c6c58fb4c3525a9ca7713b9b0a8456.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "956dead65cb4f903d114d24430eaaa518c0778c99f5f8410cc720d00151bb391"

  strings:
    $s1 = "var UGc3 = new Array(\"\\x76\",\"\\x61\",\"\\x72\",\"\\x20\",\"\\x5f\",\"\\x77\",\"\\x73\",\"\\x63\",\"\\x69\",\"\\x70\",\"\\x74" ascii

  condition:
    uint16(0) == 0x6176 and
    all of them
}