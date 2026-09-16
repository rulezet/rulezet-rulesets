rule sig_20160823_a385d02828dd9578602a74041ffee32d {
  meta:
    description = "datamaliciousorder - file 20160823_a385d02828dd9578602a74041ffee32d.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "84fab64294c9fce7c54b42e9892210976fbd66572b72de0f247fb1478ee8f925"

  strings:
    $s1 = "var Ha8 = new Array(\"\\x76\",\"\\x61\",\"\\x72\",\"\\x20\",\"\\x5f\",\"\\x77\",\"\\x73\",\"\\x63\",\"\\x69\",\"\\x70\",\"\\x74" ascii

  condition:
    uint16(0) == 0x6176 and
    all of them
}