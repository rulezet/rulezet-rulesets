rule sig_20160823_4a748e008e70fababdb4a5c1eaba4901 {
  meta:
    description = "datamaliciousorder - file 20160823_4a748e008e70fababdb4a5c1eaba4901.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "e3d73ecf9dd9f65aa150148a3c7489babf0de9f72456a540f7a6fc8db7bdf08e"

  strings:
    $s1 = "var Ha8 = new Array(\"\\x76\",\"\\x61\",\"\\x72\",\"\\x20\",\"\\x5f\",\"\\x77\",\"\\x73\",\"\\x63\",\"\\x69\",\"\\x70\",\"\\x74" ascii

  condition:
    uint16(0) == 0x6176 and
    all of them
}