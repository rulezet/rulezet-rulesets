rule sig_20160523_7cd23f94c596171e32afc53d6fc4590c {
  meta:
    description = "datamaliciousorder - file 20160523_7cd23f94c596171e32afc53d6fc4590c.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "37cff2dc580553b3a4d17ea751c1048384e700acf53666464504f2885e909321"

  strings:
    $s1 = "join('');" fullword ascii

  condition:
    uint16(0) == 0x6176 and
    all of them
}