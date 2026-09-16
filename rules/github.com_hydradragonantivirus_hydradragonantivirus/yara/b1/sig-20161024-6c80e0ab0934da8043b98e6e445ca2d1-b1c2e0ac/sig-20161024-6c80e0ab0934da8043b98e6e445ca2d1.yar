rule sig_20161024_6c80e0ab0934da8043b98e6e445ca2d1 {
  meta:
    description = "datamaliciousorder - file 20161024_6c80e0ab0934da8043b98e6e445ca2d1.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "d2d1c769ff75518fd914e3985bd4c100be6c68ed31c0628088571aa18246600b"

  strings:
    $s1 = "} while (pb++ < gd2);" fullword ascii

  condition:
    uint16(0) == 0x0a0a and
    all of them
}