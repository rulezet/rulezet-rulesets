rule sig_20161024_9a973db3f78131e1c77afb379f96f7c6 {
  meta:
    description = "datamaliciousorder - file 20161024_9a973db3f78131e1c77afb379f96f7c6.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "be2b9a4e4dbf66ca33eae1849cf20bf578d743ddebac85f9b03787e7ca075923"

  strings:
    $s1 = "} while (sg0++ < uw);" fullword ascii

  condition:
    uint16(0) == 0x0a0a and
    all of them
}