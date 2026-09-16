rule sig_20160822_28f9f06175336b7ba000ac3784b6268b {
  meta:
    description = "datamaliciousorder - file 20160822_28f9f06175336b7ba000ac3784b6268b.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "54b8007f0c611caf6a21840849778f68ab64c5e9bf522e559d01e8fc1dc3b318"

  strings:
    $s1 = "var Cp = new Array(\"\\x76\",\"\\x61\",\"\\x72\",\"\\x20\",\"\\x5f\",\"\\x77\",\"\\x73\",\"\\x63\",\"\\x69\",\"\\x70\",\"\\x74\"" ascii

  condition:
    uint16(0) == 0x6176 and
    all of them
}