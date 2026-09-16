rule sig_20160823_8215fa06715043108f16436badd7bd21 {
  meta:
    description = "datamaliciousorder - file 20160823_8215fa06715043108f16436badd7bd21.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "319d64796f85eb8e0b65107762195dd3ce2bca5d8addd3490cc30e6af9879504"

  strings:
    $s1 = "var Nt0 = new Array(\"\\x76\",\"\\x61\",\"\\x72\",\"\\x20\",\"\\x5f\",\"\\x77\",\"\\x73\",\"\\x63\",\"\\x69\",\"\\x70\",\"\\x74" ascii

  condition:
    uint16(0) == 0x6176 and
    all of them
}