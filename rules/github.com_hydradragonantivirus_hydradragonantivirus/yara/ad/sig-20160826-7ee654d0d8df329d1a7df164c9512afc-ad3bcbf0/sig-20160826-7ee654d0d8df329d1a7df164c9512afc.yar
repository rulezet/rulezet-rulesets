rule sig_20160826_7ee654d0d8df329d1a7df164c9512afc {
  meta:
    description = "datamaliciousorder - file 20160826_7ee654d0d8df329d1a7df164c9512afc.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "b60f5266fe0d7653f57108092206834c78c5e66be3487a43f834bcf8bd265656"

  strings:
    $s1 = "var Ql = new Array(\"\\x66\"+\"\",\"\\x75\"+\"\",\"\\x6e\"+\"\",\"\\x63\"+\"\",\"\\x74\"+\"\",\"\\x69\"+\"\",\"\\x6f\"+\"\",\"" ascii

  condition:
    uint16(0) == 0x7566 and
    all of them
}