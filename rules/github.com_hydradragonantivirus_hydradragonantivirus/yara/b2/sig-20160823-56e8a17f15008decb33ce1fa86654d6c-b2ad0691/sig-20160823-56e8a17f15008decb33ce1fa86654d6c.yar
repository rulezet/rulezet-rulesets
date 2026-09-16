rule sig_20160823_56e8a17f15008decb33ce1fa86654d6c {
  meta:
    description = "datamaliciousorder - file 20160823_56e8a17f15008decb33ce1fa86654d6c.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "f6c1c168ee6f043332010fb78d09100a7c7bd9536dd48bc016708fd0fe982696"

  strings:
    $s1 = "var Nt0 = new Array(\"\\x76\",\"\\x61\",\"\\x72\",\"\\x20\",\"\\x5f\",\"\\x77\",\"\\x73\",\"\\x63\",\"\\x69\",\"\\x70\",\"\\x74" ascii

  condition:
    uint16(0) == 0x6176 and
    all of them
}