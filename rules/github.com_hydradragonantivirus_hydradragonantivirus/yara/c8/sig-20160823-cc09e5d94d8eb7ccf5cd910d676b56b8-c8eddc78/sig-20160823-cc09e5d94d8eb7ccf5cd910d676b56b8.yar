rule sig_20160823_cc09e5d94d8eb7ccf5cd910d676b56b8 {
  meta:
    description = "datamaliciousorder - file 20160823_cc09e5d94d8eb7ccf5cd910d676b56b8.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "12e294fbf4065eff828fb56605096b71203adc62cb37b5fb47f22d7e08c9e828"

  strings:
    $s1 = "var Ha8 = new Array(\"\\x76\",\"\\x61\",\"\\x72\",\"\\x20\",\"\\x5f\",\"\\x77\",\"\\x73\",\"\\x63\",\"\\x69\",\"\\x70\",\"\\x74" ascii

  condition:
    uint16(0) == 0x6176 and
    all of them
}