rule sig_20160823_c77c92a4130ffc43e5db58116d468f5f {
  meta:
    description = "datamaliciousorder - file 20160823_c77c92a4130ffc43e5db58116d468f5f.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "add5c406a3106a03878a8e2e51584580cd8c311445b80c5e89230d7387e3408c"

  strings:
    $s1 = "var Ha8 = new Array(\"\\x76\",\"\\x61\",\"\\x72\",\"\\x20\",\"\\x5f\",\"\\x77\",\"\\x73\",\"\\x63\",\"\\x69\",\"\\x70\",\"\\x74" ascii

  condition:
    uint16(0) == 0x6176 and
    all of them
}