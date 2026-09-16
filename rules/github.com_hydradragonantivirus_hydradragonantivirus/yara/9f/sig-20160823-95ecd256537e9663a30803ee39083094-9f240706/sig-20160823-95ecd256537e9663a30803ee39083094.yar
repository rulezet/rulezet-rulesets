rule sig_20160823_95ecd256537e9663a30803ee39083094 {
  meta:
    description = "datamaliciousorder - file 20160823_95ecd256537e9663a30803ee39083094.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "cc71e4afd68f0562237dd87ceea022e8a15bb06c0f66257b809791fffc23e9e9"

  strings:
    $s1 = "var Ha8 = new Array(\"\\x76\",\"\\x61\",\"\\x72\",\"\\x20\",\"\\x5f\",\"\\x77\",\"\\x73\",\"\\x63\",\"\\x69\",\"\\x70\",\"\\x74" ascii

  condition:
    uint16(0) == 0x6176 and
    all of them
}