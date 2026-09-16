rule sig_20160823_de3c3aa0a6e62666bf9ca12373878e0d {
  meta:
    description = "datamaliciousorder - file 20160823_de3c3aa0a6e62666bf9ca12373878e0d.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "6c686d610d6bd1394fbc2c5fdac11f8670ad8d72bfc8f91a7b62828511080a01"

  strings:
    $s1 = "var Ha8 = new Array(\"\\x76\",\"\\x61\",\"\\x72\",\"\\x20\",\"\\x5f\",\"\\x77\",\"\\x73\",\"\\x63\",\"\\x69\",\"\\x70\",\"\\x74" ascii

  condition:
    uint16(0) == 0x6176 and
    all of them
}