rule sig_20161024_a5dafc3ce4d174e6caa1449356878dba {
  meta:
    description = "datamaliciousorder - file 20161024_a5dafc3ce4d174e6caa1449356878dba.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "609b7b75b6494286d81b9ae83c865ce579d9a4deb72eef44ede0cc338e63b1ec"

  strings:
    $s1 = "} while (rw++ < mg);" fullword ascii

  condition:
    uint16(0) == 0x0a0a and
    all of them
}