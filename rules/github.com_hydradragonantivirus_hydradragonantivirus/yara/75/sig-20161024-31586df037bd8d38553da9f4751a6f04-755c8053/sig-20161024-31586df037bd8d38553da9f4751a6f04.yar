rule sig_20161024_31586df037bd8d38553da9f4751a6f04 {
  meta:
    description = "datamaliciousorder - file 20161024_31586df037bd8d38553da9f4751a6f04.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "e6878203a4796b382c508a9fe5bd7e3659a65c909cbc2191df5239137f9c62db"

  strings:
    $s1 = "} while (ey++ < ul);" fullword ascii

  condition:
    uint16(0) == 0x0a0a and
    all of them
}