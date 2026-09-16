rule sig_20160823_b9c4b3b9e313f3c95d8682a203a99507 {
  meta:
    description = "datamaliciousorder - file 20160823_b9c4b3b9e313f3c95d8682a203a99507.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "6e110ac74880619c770a0e2aece497ccf2f120c4ee4055a7bce4da5db4ee9eb7"

  strings:
    $s1 = "var Cp = new Array(\"\\x76\",\"\\x61\",\"\\x72\",\"\\x20\",\"\\x5f\",\"\\x77\",\"\\x73\",\"\\x63\",\"\\x69\",\"\\x70\",\"\\x74\"" ascii

  condition:
    uint16(0) == 0x6176 and
    all of them
}