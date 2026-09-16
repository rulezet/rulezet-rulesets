rule sig_20160920_54b8f4f3b8d06c87b71c8bd0351ab64a {
  meta:
    description = "datamaliciousorder - file 20160920_54b8f4f3b8d06c87b71c8bd0351ab64a.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "094a76fe1f5c4d483205923001012a52e73a18f145cc1f7a88ab7f07b4c27a8e"

  strings:
    $s1 = "split('msemse');" fullword ascii

  condition:
    uint16(0) == 0x2f0a and
    all of them
}