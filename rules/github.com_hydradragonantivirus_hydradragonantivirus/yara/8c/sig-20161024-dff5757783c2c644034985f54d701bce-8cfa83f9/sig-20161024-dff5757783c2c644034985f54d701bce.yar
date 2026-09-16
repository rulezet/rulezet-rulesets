rule sig_20161024_dff5757783c2c644034985f54d701bce {
  meta:
    description = "datamaliciousorder - file 20161024_dff5757783c2c644034985f54d701bce.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "f662f3cb1653a3cb0f0b015ade087a72aae142eff1c66da87f16ed49f6f837df"

  strings:
    $s1 = "} while (yd++ < gi);" fullword ascii

  condition:
    uint16(0) == 0x0a0a and
    all of them
}