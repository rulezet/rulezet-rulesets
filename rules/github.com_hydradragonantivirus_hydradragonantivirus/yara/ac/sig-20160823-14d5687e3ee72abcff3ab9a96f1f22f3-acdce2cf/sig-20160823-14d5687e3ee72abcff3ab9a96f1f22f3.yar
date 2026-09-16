rule sig_20160823_14d5687e3ee72abcff3ab9a96f1f22f3 {
  meta:
    description = "datamaliciousorder - file 20160823_14d5687e3ee72abcff3ab9a96f1f22f3.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "cf29608b84932ae48383b64d4eedb70cacc630d6faa72214af595e13f66e67c3"

  strings:
    $s1 = "var Cp = new Array(\"\\x76\",\"\\x61\",\"\\x72\",\"\\x20\",\"\\x5f\",\"\\x77\",\"\\x73\",\"\\x63\",\"\\x69\",\"\\x70\",\"\\x74\"" ascii

  condition:
    uint16(0) == 0x6176 and
    all of them
}