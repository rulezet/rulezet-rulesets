rule sig_20160823_6eed16c710294980078493fa7e6a4795 {
  meta:
    description = "datamaliciousorder - file 20160823_6eed16c710294980078493fa7e6a4795.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "31faf9cda988436d690a3d49418850fb62d29c0673565882029c1a51e8c4a86e"

  strings:
    $s1 = "var Ha8 = new Array(\"\\x76\",\"\\x61\",\"\\x72\",\"\\x20\",\"\\x5f\",\"\\x77\",\"\\x73\",\"\\x63\",\"\\x69\",\"\\x70\",\"\\x74" ascii

  condition:
    uint16(0) == 0x6176 and
    all of them
}