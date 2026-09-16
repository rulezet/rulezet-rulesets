rule sig_20160823_39cd7335c576525e094e82c0d888f50d {
  meta:
    description = "datamaliciousorder - file 20160823_39cd7335c576525e094e82c0d888f50d.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "8d1bc55acc54ae4766641991681dbecd475299edd6a8a0d89a3bf0f2a042bcf6"

  strings:
    $s1 = "var Ha8 = new Array(\"\\x76\",\"\\x61\",\"\\x72\",\"\\x20\",\"\\x5f\",\"\\x77\",\"\\x73\",\"\\x63\",\"\\x69\",\"\\x70\",\"\\x74" ascii

  condition:
    uint16(0) == 0x6176 and
    all of them
}