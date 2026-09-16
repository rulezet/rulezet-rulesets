rule sig_20160822_b35b89c243279b3de952c0e75d36934e {
  meta:
    description = "datamaliciousorder - file 20160822_b35b89c243279b3de952c0e75d36934e.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "8f8962b7f1745943681cb63b48ac7d71bce4cb72b8aa654c85f014a6eada7f52"

  strings:
    $s1 = "var UGc3 = new Array(\"\\x76\",\"\\x61\",\"\\x72\",\"\\x20\",\"\\x5f\",\"\\x77\",\"\\x73\",\"\\x63\",\"\\x69\",\"\\x70\",\"\\x74" ascii

  condition:
    uint16(0) == 0x6176 and
    all of them
}