rule sig_20160823_2eed17ad4e84be96d4359d3d9863ee4f {
  meta:
    description = "datamaliciousorder - file 20160823_2eed17ad4e84be96d4359d3d9863ee4f.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "ad0a6915de7fb2e2418c8bcdc02d56ebbd18987492f792f467375eecbe29413d"

  strings:
    $s1 = "var Nt0 = new Array(\"\\x76\",\"\\x61\",\"\\x72\",\"\\x20\",\"\\x5f\",\"\\x77\",\"\\x73\",\"\\x63\",\"\\x69\",\"\\x70\",\"\\x74" ascii

  condition:
    uint16(0) == 0x6176 and
    all of them
}