rule sig_20161024_ef10bbe241c023300c9831371b0aaddb {
  meta:
    description = "datamaliciousorder - file 20161024_ef10bbe241c023300c9831371b0aaddb.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "a1d1ea3380e44044744661a2ae4bbce3aa9a15d2a285e5c8883023c249965ca9"

  strings:
    $s1 = "} while (cy++ < dz);" fullword ascii

  condition:
    uint16(0) == 0x0a0a and
    all of them
}