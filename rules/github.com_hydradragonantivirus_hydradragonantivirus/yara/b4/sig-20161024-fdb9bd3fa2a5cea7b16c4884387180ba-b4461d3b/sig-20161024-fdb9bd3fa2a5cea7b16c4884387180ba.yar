rule sig_20161024_fdb9bd3fa2a5cea7b16c4884387180ba {
  meta:
    description = "datamaliciousorder - file 20161024_fdb9bd3fa2a5cea7b16c4884387180ba.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "b64465db4169d9e3448fc515ad54f495bff407d4d443168fb96d263f86d92e8b"

  strings:
    $s1 = "} while (xu++ < zz0);" fullword ascii

  condition:
    uint16(0) == 0x0a0a and
    all of them
}