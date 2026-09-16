rule sig_20160823_dc632e934e8aca5452d5b72e14365285 {
  meta:
    description = "datamaliciousorder - file 20160823_dc632e934e8aca5452d5b72e14365285.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "27900d000d90d3eaee46aedb967f8425fbaf09a7778d82669fca850071198c7e"

  strings:
    $s1 = "var Ha8 = new Array(\"\\x76\",\"\\x61\",\"\\x72\",\"\\x20\",\"\\x5f\",\"\\x77\",\"\\x73\",\"\\x63\",\"\\x69\",\"\\x70\",\"\\x74" ascii

  condition:
    uint16(0) == 0x6176 and
    all of them
}