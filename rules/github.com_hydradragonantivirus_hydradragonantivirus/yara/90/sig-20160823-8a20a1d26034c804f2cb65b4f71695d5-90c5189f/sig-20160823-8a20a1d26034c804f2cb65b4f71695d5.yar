rule sig_20160823_8a20a1d26034c804f2cb65b4f71695d5 {
  meta:
    description = "datamaliciousorder - file 20160823_8a20a1d26034c804f2cb65b4f71695d5.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "01da891615f2084d1e5a36fd1bfc087491783324cc161a18eb17f20f263d59f6"

  strings:
    $s1 = "var Ha8 = new Array(\"\\x76\",\"\\x61\",\"\\x72\",\"\\x20\",\"\\x5f\",\"\\x77\",\"\\x73\",\"\\x63\",\"\\x69\",\"\\x70\",\"\\x74" ascii

  condition:
    uint16(0) == 0x6176 and
    all of them
}