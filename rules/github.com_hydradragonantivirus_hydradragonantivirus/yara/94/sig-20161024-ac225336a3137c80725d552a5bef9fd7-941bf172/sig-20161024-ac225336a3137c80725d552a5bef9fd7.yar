rule sig_20161024_ac225336a3137c80725d552a5bef9fd7 {
  meta:
    description = "datamaliciousorder - file 20161024_ac225336a3137c80725d552a5bef9fd7.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "3046fcaedbf927363cddebdf2928a71b753a58c1a393baa8a98d350f85fdddb4"

  strings:
    $s1 = "} while (su++ < ni);" fullword ascii

  condition:
    uint16(0) == 0x0a0a and
    all of them
}