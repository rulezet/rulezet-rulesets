rule sig_20160823_fa8bd87e41c7d36fc70aa78b151bdb68 {
  meta:
    description = "datamaliciousorder - file 20160823_fa8bd87e41c7d36fc70aa78b151bdb68.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "dff04268080d116a29a0e4efd9a07b397ef5865a16bcb3e7b30aefa791b4e32a"

  strings:
    $s1 = "var Nt0 = new Array(\"\\x76\",\"\\x61\",\"\\x72\",\"\\x20\",\"\\x5f\",\"\\x77\",\"\\x73\",\"\\x63\",\"\\x69\",\"\\x70\",\"\\x74" ascii

  condition:
    uint16(0) == 0x6176 and
    all of them
}