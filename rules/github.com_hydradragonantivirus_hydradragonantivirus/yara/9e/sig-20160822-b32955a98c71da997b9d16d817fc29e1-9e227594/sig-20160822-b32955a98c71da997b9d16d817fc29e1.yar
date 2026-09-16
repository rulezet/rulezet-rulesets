rule sig_20160822_b32955a98c71da997b9d16d817fc29e1 {
  meta:
    description = "datamaliciousorder - file 20160822_b32955a98c71da997b9d16d817fc29e1.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "4e5256365df11b6fd53c5dc934dd8805db044482a805b181fe8922bb9fddb337"

  strings:
    $s1 = "var Cp = new Array(\"\\x76\",\"\\x61\",\"\\x72\",\"\\x20\",\"\\x5f\",\"\\x77\",\"\\x73\",\"\\x63\",\"\\x69\",\"\\x70\",\"\\x74\"" ascii

  condition:
    uint16(0) == 0x6176 and
    all of them
}