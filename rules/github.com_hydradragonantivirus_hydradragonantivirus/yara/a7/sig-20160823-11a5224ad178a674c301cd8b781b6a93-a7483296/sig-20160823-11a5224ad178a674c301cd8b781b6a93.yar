rule sig_20160823_11a5224ad178a674c301cd8b781b6a93 {
  meta:
    description = "datamaliciousorder - file 20160823_11a5224ad178a674c301cd8b781b6a93.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "a587224a0624afec87a8ee17ea59de823f6e8f979657ddac20a59c161bc8dc6a"

  strings:
    $s1 = "var Cp = new Array(\"\\x76\",\"\\x61\",\"\\x72\",\"\\x20\",\"\\x5f\",\"\\x77\",\"\\x73\",\"\\x63\",\"\\x69\",\"\\x70\",\"\\x74\"" ascii

  condition:
    uint16(0) == 0x6176 and
    all of them
}