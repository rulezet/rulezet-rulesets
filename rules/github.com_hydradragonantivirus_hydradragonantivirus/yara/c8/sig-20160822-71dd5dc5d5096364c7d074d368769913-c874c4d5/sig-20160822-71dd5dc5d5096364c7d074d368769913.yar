rule sig_20160822_71dd5dc5d5096364c7d074d368769913 {
  meta:
    description = "datamaliciousorder - file 20160822_71dd5dc5d5096364c7d074d368769913.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "db2e601912d681a434d8b9128ffc67c6f27b57bdca51f9292f4b1f828b42f279"

  strings:
    $s1 = "var Cp = new Array(\"\\x76\",\"\\x61\",\"\\x72\",\"\\x20\",\"\\x5f\",\"\\x77\",\"\\x73\",\"\\x63\",\"\\x69\",\"\\x70\",\"\\x74\"" ascii

  condition:
    uint16(0) == 0x6176 and
    all of them
}