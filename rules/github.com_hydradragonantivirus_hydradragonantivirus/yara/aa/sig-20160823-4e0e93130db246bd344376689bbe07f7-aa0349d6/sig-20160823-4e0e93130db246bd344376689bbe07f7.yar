rule sig_20160823_4e0e93130db246bd344376689bbe07f7 {
  meta:
    description = "datamaliciousorder - file 20160823_4e0e93130db246bd344376689bbe07f7.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "d23405c0c0a2933351ea029e0b014f19f0f794c8331d52c07938833281b28a13"

  strings:
    $s1 = "var Ha8 = new Array(\"\\x76\",\"\\x61\",\"\\x72\",\"\\x20\",\"\\x5f\",\"\\x77\",\"\\x73\",\"\\x63\",\"\\x69\",\"\\x70\",\"\\x74" ascii

  condition:
    uint16(0) == 0x6176 and
    all of them
}