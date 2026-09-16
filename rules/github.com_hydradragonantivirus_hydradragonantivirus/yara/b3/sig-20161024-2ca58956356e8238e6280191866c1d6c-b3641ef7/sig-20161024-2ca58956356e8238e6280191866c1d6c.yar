rule sig_20161024_2ca58956356e8238e6280191866c1d6c {
  meta:
    description = "datamaliciousorder - file 20161024_2ca58956356e8238e6280191866c1d6c.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "4e1324e1061b51df5244621a1f4fc5c9598b9e4495005d163a57e9b8c5fc5b13"

  strings:
    $s1 = "} while (ve++ < qs);" fullword ascii

  condition:
    uint16(0) == 0x0a0a and
    all of them
}