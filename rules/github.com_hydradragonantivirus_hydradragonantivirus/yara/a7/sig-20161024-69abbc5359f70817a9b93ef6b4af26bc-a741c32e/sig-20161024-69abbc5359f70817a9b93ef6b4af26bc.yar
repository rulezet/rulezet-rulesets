rule sig_20161024_69abbc5359f70817a9b93ef6b4af26bc {
  meta:
    description = "datamaliciousorder - file 20161024_69abbc5359f70817a9b93ef6b4af26bc.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "ada72b03d6282437bf36ea50e57e7f48961d309769f1cc62fcc92446e3ce9fe6"

  strings:
    $s1 = "} while (jc++ < bc0);" fullword ascii

  condition:
    uint16(0) == 0x0a0a and
    all of them
}