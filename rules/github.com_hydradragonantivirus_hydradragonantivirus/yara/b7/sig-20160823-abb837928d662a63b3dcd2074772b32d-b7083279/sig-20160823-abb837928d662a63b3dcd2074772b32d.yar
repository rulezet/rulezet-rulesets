rule sig_20160823_abb837928d662a63b3dcd2074772b32d {
  meta:
    description = "datamaliciousorder - file 20160823_abb837928d662a63b3dcd2074772b32d.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "8366a2147d5c8003159fb31a8e570d5b6795f5596922474a95c84d8fab90c85d"

  strings:
    $s1 = "var Nt0 = new Array(\"\\x76\",\"\\x61\",\"\\x72\",\"\\x20\",\"\\x5f\",\"\\x77\",\"\\x73\",\"\\x63\",\"\\x69\",\"\\x70\",\"\\x74" ascii

  condition:
    uint16(0) == 0x6176 and
    all of them
}