rule sig_20160823_d7a851e29a416ad92db03529c9e5895e {
  meta:
    description = "datamaliciousorder - file 20160823_d7a851e29a416ad92db03529c9e5895e.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "10b95627ae7a9c754486f7e1c50a06e4eace5c669a3e6491bf88b71a7c469749"

  strings:
    $s1 = "var Ha8 = new Array(\"\\x76\",\"\\x61\",\"\\x72\",\"\\x20\",\"\\x5f\",\"\\x77\",\"\\x73\",\"\\x63\",\"\\x69\",\"\\x70\",\"\\x74" ascii

  condition:
    uint16(0) == 0x6176 and
    all of them
}