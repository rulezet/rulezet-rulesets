rule sig_20160823_a8c9ca4cb73ab961c33b329f082604b0 {
  meta:
    description = "datamaliciousorder - file 20160823_a8c9ca4cb73ab961c33b329f082604b0.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "9a7d830b65f81eeb4e98041df2ba8610141b615b3dc59fe8bb93a19b9701d8a1"

  strings:
    $s1 = "var Cp = new Array(\"\\x76\",\"\\x61\",\"\\x72\",\"\\x20\",\"\\x5f\",\"\\x77\",\"\\x73\",\"\\x63\",\"\\x69\",\"\\x70\",\"\\x74\"" ascii

  condition:
    uint16(0) == 0x6176 and
    all of them
}