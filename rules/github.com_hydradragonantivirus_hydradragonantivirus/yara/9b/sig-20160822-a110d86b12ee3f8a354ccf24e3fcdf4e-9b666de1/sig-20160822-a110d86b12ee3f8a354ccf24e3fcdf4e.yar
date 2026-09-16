rule sig_20160822_a110d86b12ee3f8a354ccf24e3fcdf4e {
  meta:
    description = "datamaliciousorder - file 20160822_a110d86b12ee3f8a354ccf24e3fcdf4e.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "87424914a718d3a8859ad258f08b2476dd46df3b193498a4d657567e2375037d"

  strings:
    $s1 = "var Cp = new Array(\"\\x76\",\"\\x61\",\"\\x72\",\"\\x20\",\"\\x5f\",\"\\x77\",\"\\x73\",\"\\x63\",\"\\x69\",\"\\x70\",\"\\x74\"" ascii

  condition:
    uint16(0) == 0x6176 and
    all of them
}