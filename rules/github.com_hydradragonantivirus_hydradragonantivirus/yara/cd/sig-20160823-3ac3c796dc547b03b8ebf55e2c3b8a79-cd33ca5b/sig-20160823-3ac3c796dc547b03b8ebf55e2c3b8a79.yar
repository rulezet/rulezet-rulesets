rule sig_20160823_3ac3c796dc547b03b8ebf55e2c3b8a79 {
  meta:
    description = "datamaliciousorder - file 20160823_3ac3c796dc547b03b8ebf55e2c3b8a79.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "39f431228ad511867b599184cf89a870b2a4780ca869851fe5303a824770c70c"

  strings:
    $s1 = "var Ha8 = new Array(\"\\x76\",\"\\x61\",\"\\x72\",\"\\x20\",\"\\x5f\",\"\\x77\",\"\\x73\",\"\\x63\",\"\\x69\",\"\\x70\",\"\\x74" ascii

  condition:
    uint16(0) == 0x6176 and
    all of them
}