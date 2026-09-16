rule sig_20160822_5ed91f407a27e771d5a53d06b9361f64 {
  meta:
    description = "datamaliciousorder - file 20160822_5ed91f407a27e771d5a53d06b9361f64.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "40ffc62fafc20c94243f1cb6b7e9b9018c5648892d9845644f2fc50beb9c97a4"

  strings:
    $s1 = "var Cp = new Array(\"\\x76\",\"\\x61\",\"\\x72\",\"\\x20\",\"\\x5f\",\"\\x77\",\"\\x73\",\"\\x63\",\"\\x69\",\"\\x70\",\"\\x74\"" ascii

  condition:
    uint16(0) == 0x6176 and
    all of them
}