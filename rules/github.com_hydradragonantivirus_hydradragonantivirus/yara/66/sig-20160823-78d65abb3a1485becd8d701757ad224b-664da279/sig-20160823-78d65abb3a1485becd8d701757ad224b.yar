rule sig_20160823_78d65abb3a1485becd8d701757ad224b {
  meta:
    description = "datamaliciousorder - file 20160823_78d65abb3a1485becd8d701757ad224b.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "fb1d542a98b4d1b75cf2fc394a668a0fc6ef1a7ad6e7f4b9998f75b9d26868f6"

  strings:
    $s1 = "var Ha8 = new Array(\"\\x76\",\"\\x61\",\"\\x72\",\"\\x20\",\"\\x5f\",\"\\x77\",\"\\x73\",\"\\x63\",\"\\x69\",\"\\x70\",\"\\x74" ascii

  condition:
    uint16(0) == 0x6176 and
    all of them
}