rule sig_20160823_4c08e0d00c04a7fd31e78e1e6934080b {
  meta:
    description = "datamaliciousorder - file 20160823_4c08e0d00c04a7fd31e78e1e6934080b.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "eccf0a7098ca83baf1e357e9f398c03ee79fddfa4baa0362d39b0a2435281dc7"

  strings:
    $s1 = "var Cp = new Array(\"\\x76\",\"\\x61\",\"\\x72\",\"\\x20\",\"\\x5f\",\"\\x77\",\"\\x73\",\"\\x63\",\"\\x69\",\"\\x70\",\"\\x74\"" ascii

  condition:
    uint16(0) == 0x6176 and
    all of them
}