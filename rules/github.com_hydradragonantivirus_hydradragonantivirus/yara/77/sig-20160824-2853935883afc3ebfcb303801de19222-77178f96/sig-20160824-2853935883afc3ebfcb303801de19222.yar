rule sig_20160824_2853935883afc3ebfcb303801de19222 {
  meta:
    description = "datamaliciousorder - file 20160824_2853935883afc3ebfcb303801de19222.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "c541ce2fe9949039d8a025168bff37a152b6e4b17aabe27baca981170ce9242d"

  strings:
    $s1 = "var DOh = new Array(\"\\x66\",\"\\x75\",\"\\x6e\",\"\\x63\",\"\\x74\",\"\\x69\",\"\\x6f\",\"\\x20\",\"\\x6b\",\"\\x28\",\"\\x29" ascii

  condition:
    uint16(0) == 0x7566 and
    all of them
}