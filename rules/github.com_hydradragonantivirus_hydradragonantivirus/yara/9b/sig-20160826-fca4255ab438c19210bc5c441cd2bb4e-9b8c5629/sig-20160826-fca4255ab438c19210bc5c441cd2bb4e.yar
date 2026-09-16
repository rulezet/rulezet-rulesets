rule sig_20160826_fca4255ab438c19210bc5c441cd2bb4e {
  meta:
    description = "datamaliciousorder - file 20160826_fca4255ab438c19210bc5c441cd2bb4e.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "c7f8d21ddfafe49b6ad5743dfba89a47d47328cad41016c12555809a33ab8480"

  strings:
    $s1 = "var Ql = new Array(\"\\x66\"+\"\",\"\\x75\"+\"\",\"\\x6e\"+\"\",\"\\x63\"+\"\",\"\\x74\"+\"\",\"\\x69\"+\"\",\"\\x6f\"+\"\",\"" ascii

  condition:
    uint16(0) == 0x7566 and
    all of them
}