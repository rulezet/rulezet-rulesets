rule sig_20161024_fd288b3b9f35cf8d2e9760fb8fb24565 {
  meta:
    description = "datamaliciousorder - file 20161024_fd288b3b9f35cf8d2e9760fb8fb24565.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "f48e3bf939dd0f1eaabcc5d9191f0cb93fa7c7ee127257ed07549d3c950789f7"

  strings:
    $s1 = "} while (ib++ < yk);" fullword ascii

  condition:
    uint16(0) == 0x0a0a and
    all of them
}