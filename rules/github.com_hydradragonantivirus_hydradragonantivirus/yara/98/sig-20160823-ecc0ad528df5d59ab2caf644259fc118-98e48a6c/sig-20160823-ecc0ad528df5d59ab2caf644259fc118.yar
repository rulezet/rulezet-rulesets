rule sig_20160823_ecc0ad528df5d59ab2caf644259fc118 {
  meta:
    description = "datamaliciousorder - file 20160823_ecc0ad528df5d59ab2caf644259fc118.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "bdcd194dd3eef463550bdbce70665ecafe7d6f6122681fac026bf026fb0ea4d7"

  strings:
    $s1 = "var Cp = new Array(\"\\x76\",\"\\x61\",\"\\x72\",\"\\x20\",\"\\x5f\",\"\\x77\",\"\\x73\",\"\\x63\",\"\\x69\",\"\\x70\",\"\\x74\"" ascii

  condition:
    uint16(0) == 0x6176 and
    all of them
}