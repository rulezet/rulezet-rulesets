rule sig_20160523_0bf453eafc483d4b33ee115cf888f59d {
  meta:
    description = "datamaliciousorder - file 20160523_0bf453eafc483d4b33ee115cf888f59d.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "b24c719a38e3e10f544f7cdb595f488d6af3723b87876c3e780ebaf9912ed688"

  strings:
    $s1 = "verse().join('');" fullword ascii

  condition:
    uint16(0) == 0x6176 and
    all of them
}