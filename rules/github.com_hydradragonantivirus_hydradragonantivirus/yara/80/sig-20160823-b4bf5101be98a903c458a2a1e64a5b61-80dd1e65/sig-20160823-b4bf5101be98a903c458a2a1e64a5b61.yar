rule sig_20160823_b4bf5101be98a903c458a2a1e64a5b61 {
  meta:
    description = "datamaliciousorder - file 20160823_b4bf5101be98a903c458a2a1e64a5b61.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "c3ce8a7a761e25d4b32a70c8851b600b1b541b494e959a39db1cfa9f0c2781ce"

  strings:
    $s1 = "var Ha8 = new Array(\"\\x76\",\"\\x61\",\"\\x72\",\"\\x20\",\"\\x5f\",\"\\x77\",\"\\x73\",\"\\x63\",\"\\x69\",\"\\x70\",\"\\x74" ascii

  condition:
    uint16(0) == 0x6176 and
    all of them
}