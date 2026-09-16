rule sig_20161024_2f7175e2fdc0d42192fe498e542e03de {
  meta:
    description = "datamaliciousorder - file 20161024_2f7175e2fdc0d42192fe498e542e03de.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "02984b64cc5c9c6540bcb543799364a1069e6a5e5fca9c47074109dd775305e2"

  strings:
    $s1 = "} while (gq++ < zz);" fullword ascii

  condition:
    uint16(0) == 0x0a0a and
    all of them
}