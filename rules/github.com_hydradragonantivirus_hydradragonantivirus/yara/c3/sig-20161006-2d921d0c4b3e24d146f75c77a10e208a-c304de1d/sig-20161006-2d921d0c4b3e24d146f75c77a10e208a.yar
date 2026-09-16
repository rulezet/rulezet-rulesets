rule sig_20161006_2d921d0c4b3e24d146f75c77a10e208a {
  meta:
    description = "datamaliciousorder - file 20161006_2d921d0c4b3e24d146f75c77a10e208a.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "a508cc3914b557349a22a58281ea47a60a823cd1abf9bda56ee71c46d429332b"

  strings:
    $s1 = "} while (gm++ < fe0);" fullword ascii

  condition:
    uint16(0) == 0x2f0a and
    all of them
}