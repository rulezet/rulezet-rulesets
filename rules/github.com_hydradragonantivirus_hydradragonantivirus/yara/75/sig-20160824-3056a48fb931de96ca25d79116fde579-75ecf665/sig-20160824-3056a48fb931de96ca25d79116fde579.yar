rule sig_20160824_3056a48fb931de96ca25d79116fde579 {
  meta:
    description = "datamaliciousorder - file 20160824_3056a48fb931de96ca25d79116fde579.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "8895f55986ad6c098654ca29e2117bca83999a5211f96f2654b495d7b2444f2e"

  strings:
    $s1 = "var Li4 = new Array(\"\\x66\",\"\\x75\",\"\\x6e\",\"\\x63\",\"\\x74\",\"\\x69\",\"\\x6f\",\"\\x20\",\"\\x6b\",\"\\x28\",\"\\x29" ascii

  condition:
    uint16(0) == 0x7566 and
    all of them
}