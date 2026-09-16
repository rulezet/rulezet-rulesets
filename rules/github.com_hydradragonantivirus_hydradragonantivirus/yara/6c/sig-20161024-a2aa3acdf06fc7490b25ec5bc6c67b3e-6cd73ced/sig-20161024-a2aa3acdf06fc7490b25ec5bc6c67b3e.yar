rule sig_20161024_a2aa3acdf06fc7490b25ec5bc6c67b3e {
  meta:
    description = "datamaliciousorder - file 20161024_a2aa3acdf06fc7490b25ec5bc6c67b3e.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "5f208821af72d276c1665d3472d186372091676444a4371e956176997fed0fc7"

  strings:
    $s1 = "} while (xm++ < eh);" fullword ascii

  condition:
    uint16(0) == 0x0a0a and
    all of them
}