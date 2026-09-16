rule sig_20161024_2fe27596e7da4ca704cf12b76c243b29 {
  meta:
    description = "datamaliciousorder - file 20161024_2fe27596e7da4ca704cf12b76c243b29.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "d1f81b30d430776b61bc73b3257835eb1fd446d7ce894d86e27c239477b96791"

  strings:
    $s1 = "} while (ml++ < gz);" fullword ascii

  condition:
    uint16(0) == 0x0a0a and
    all of them
}