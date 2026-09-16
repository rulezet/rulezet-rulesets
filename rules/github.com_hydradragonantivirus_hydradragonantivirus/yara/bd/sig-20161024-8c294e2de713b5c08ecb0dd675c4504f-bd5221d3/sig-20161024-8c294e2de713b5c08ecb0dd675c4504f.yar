rule sig_20161024_8c294e2de713b5c08ecb0dd675c4504f {
  meta:
    description = "datamaliciousorder - file 20161024_8c294e2de713b5c08ecb0dd675c4504f.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "8afe28472a8855b100bb4769b8025562b68ce09cf582e9d286b7124a4848b35f"

  strings:
    $s1 = "} while (of++ < gi);" fullword ascii

  condition:
    uint16(0) == 0x0a0a and
    all of them
}