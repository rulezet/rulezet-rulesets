rule sig_20160823_e67dac00f8bbd86f627783a42b493ec8 {
  meta:
    description = "datamaliciousorder - file 20160823_e67dac00f8bbd86f627783a42b493ec8.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "ddb73a6600157fc2337d490f0afa742bd50fa0853e6de9509bfd2dd184eeec15"

  strings:
    $s1 = "var Nt0 = new Array(\"\\x76\",\"\\x61\",\"\\x72\",\"\\x20\",\"\\x5f\",\"\\x77\",\"\\x73\",\"\\x63\",\"\\x69\",\"\\x70\",\"\\x74" ascii

  condition:
    uint16(0) == 0x6176 and
    all of them
}