rule sig_20161024_dc7b9a9a7e5559808eef988fff7add04 {
  meta:
    description = "datamaliciousorder - file 20161024_dc7b9a9a7e5559808eef988fff7add04.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "4fa1599741b753b848e90659aaec2212a23f7e194c485a5e9fe6a81e4b2b58cf"

  strings:
    $s1 = "} while (uj++ < qo);" fullword ascii

  condition:
    uint16(0) == 0x0a0a and
    all of them
}