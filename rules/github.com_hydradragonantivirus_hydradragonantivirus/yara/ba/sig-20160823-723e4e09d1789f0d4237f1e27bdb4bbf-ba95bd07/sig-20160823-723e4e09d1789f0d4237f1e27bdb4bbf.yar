rule sig_20160823_723e4e09d1789f0d4237f1e27bdb4bbf {
  meta:
    description = "datamaliciousorder - file 20160823_723e4e09d1789f0d4237f1e27bdb4bbf.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "1809c82fc7139a14b4947b372ad08bd416af1e79828abcdf65a5ff757194367c"

  strings:
    $s1 = "var Cp = new Array(\"\\x76\",\"\\x61\",\"\\x72\",\"\\x20\",\"\\x5f\",\"\\x77\",\"\\x73\",\"\\x63\",\"\\x69\",\"\\x70\",\"\\x74\"" ascii

  condition:
    uint16(0) == 0x6176 and
    all of them
}