rule sig_20160823_f8fa29c83714f2f316f15d4c4d05b322 {
  meta:
    description = "datamaliciousorder - file 20160823_f8fa29c83714f2f316f15d4c4d05b322.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "a11bf0975ffa5b694aee550b9326f1093506ffe119b0cec9d3dc0654e15b618e"

  strings:
    $s1 = "var Nt0 = new Array(\"\\x76\",\"\\x61\",\"\\x72\",\"\\x20\",\"\\x5f\",\"\\x77\",\"\\x73\",\"\\x63\",\"\\x69\",\"\\x70\",\"\\x74" ascii

  condition:
    uint16(0) == 0x6176 and
    all of them
}