rule sig_20161024_1b6fe1455cd6284e70ee6095f5075273 {
  meta:
    description = "datamaliciousorder - file 20161024_1b6fe1455cd6284e70ee6095f5075273.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "96023acb50d8390421facf3b764a4198e0f2b944ca43ed4be0109ef843537e43"

  strings:
    $s1 = "} while (yp++ < tg);" fullword ascii

  condition:
    uint16(0) == 0x0a0a and
    all of them
}