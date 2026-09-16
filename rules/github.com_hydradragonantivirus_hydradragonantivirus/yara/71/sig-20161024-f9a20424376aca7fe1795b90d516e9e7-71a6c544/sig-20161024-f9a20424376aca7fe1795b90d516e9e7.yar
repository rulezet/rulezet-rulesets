rule sig_20161024_f9a20424376aca7fe1795b90d516e9e7 {
  meta:
    description = "datamaliciousorder - file 20161024_f9a20424376aca7fe1795b90d516e9e7.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "9e4f1fb32cfcb3dc7f9120a88462236f457303e83109fe03a9c34b28a9902e28"

  strings:
    $s1 = "} while (uc++ < eu);" fullword ascii

  condition:
    uint16(0) == 0x0a0a and
    all of them
}