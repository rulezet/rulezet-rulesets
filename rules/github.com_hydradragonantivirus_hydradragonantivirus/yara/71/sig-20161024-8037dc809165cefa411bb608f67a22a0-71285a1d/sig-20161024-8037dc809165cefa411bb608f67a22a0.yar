rule sig_20161024_8037dc809165cefa411bb608f67a22a0 {
  meta:
    description = "datamaliciousorder - file 20161024_8037dc809165cefa411bb608f67a22a0.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "05fb233693c51ea7d1ff5f2dc10994976cc2258f3b8315b751e7ac7912cf8662"

  strings:
    $s1 = "} while (kh0++ < eu0);" fullword ascii

  condition:
    uint16(0) == 0x0a0a and
    all of them
}