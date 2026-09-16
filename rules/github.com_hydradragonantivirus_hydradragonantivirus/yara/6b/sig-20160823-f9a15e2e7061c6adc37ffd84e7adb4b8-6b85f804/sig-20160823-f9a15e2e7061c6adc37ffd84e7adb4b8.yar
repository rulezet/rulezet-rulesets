rule sig_20160823_f9a15e2e7061c6adc37ffd84e7adb4b8 {
  meta:
    description = "datamaliciousorder - file 20160823_f9a15e2e7061c6adc37ffd84e7adb4b8.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "5679302a70141a0b50dbd81168364200396069b0607198ccc89ece6bda891319"

  strings:
    $s1 = "var Ha8 = new Array(\"\\x76\",\"\\x61\",\"\\x72\",\"\\x20\",\"\\x5f\",\"\\x77\",\"\\x73\",\"\\x63\",\"\\x69\",\"\\x70\",\"\\x74" ascii

  condition:
    uint16(0) == 0x6176 and
    all of them
}