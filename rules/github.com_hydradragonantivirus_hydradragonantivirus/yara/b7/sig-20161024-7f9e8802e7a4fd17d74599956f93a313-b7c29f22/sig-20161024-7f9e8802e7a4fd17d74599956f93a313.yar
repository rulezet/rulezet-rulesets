rule sig_20161024_7f9e8802e7a4fd17d74599956f93a313 {
  meta:
    description = "datamaliciousorder - file 20161024_7f9e8802e7a4fd17d74599956f93a313.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "d491f4752f9e12ebbf1741199d951a3475bf678ff750962f6c93ccb5a5b832e8"

  strings:
    $s1 = "} while (dm++ < un0);" fullword ascii

  condition:
    uint16(0) == 0x0a0a and
    all of them
}