rule sig_20160826_8d1547d9dfe7b8015d28f1112b916305 {
  meta:
    description = "datamaliciousorder - file 20160826_8d1547d9dfe7b8015d28f1112b916305.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "33015814267adf40330c65efd2ed88ad0b7bed0e3bd1595c98c7e0eababef550"

  strings:
    $s1 = "var Ql = new Array(\"\\x66\"+\"\",\"\\x75\"+\"\",\"\\x6e\"+\"\",\"\\x63\"+\"\",\"\\x74\"+\"\",\"\\x69\"+\"\",\"\\x6f\"+\"\",\"" ascii

  condition:
    uint16(0) == 0x7566 and
    all of them
}