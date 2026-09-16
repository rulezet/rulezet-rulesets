rule sig_20161024_3ec8b22454d1cd88842769317dadab1e {
  meta:
    description = "datamaliciousorder - file 20161024_3ec8b22454d1cd88842769317dadab1e.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "daeb130178da4282ec431c6da6149c80d4e51c2e6aeb83ae2480feb2da33cb4c"

  strings:
    $s1 = "} while (kx++ < qo);" fullword ascii

  condition:
    uint16(0) == 0x0a0a and
    all of them
}