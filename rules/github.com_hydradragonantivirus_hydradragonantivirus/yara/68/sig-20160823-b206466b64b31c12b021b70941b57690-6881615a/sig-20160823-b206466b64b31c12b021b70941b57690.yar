rule sig_20160823_b206466b64b31c12b021b70941b57690 {
  meta:
    description = "datamaliciousorder - file 20160823_b206466b64b31c12b021b70941b57690.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "1e5b34eca2c308fe683cf136e43a3de8a88a2a054bc838b927c17001b948eb94"

  strings:
    $s1 = "var Ha8 = new Array(\"\\x76\",\"\\x61\",\"\\x72\",\"\\x20\",\"\\x5f\",\"\\x77\",\"\\x73\",\"\\x63\",\"\\x69\",\"\\x70\",\"\\x74" ascii

  condition:
    uint16(0) == 0x6176 and
    all of them
}