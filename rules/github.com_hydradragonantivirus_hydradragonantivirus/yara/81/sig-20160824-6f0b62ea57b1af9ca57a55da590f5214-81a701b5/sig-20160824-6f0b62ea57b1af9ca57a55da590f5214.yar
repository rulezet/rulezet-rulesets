rule sig_20160824_6f0b62ea57b1af9ca57a55da590f5214 {
  meta:
    description = "datamaliciousorder - file 20160824_6f0b62ea57b1af9ca57a55da590f5214.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "95d574ac4626b1aa0bd730837f6205bde2a10f22defdf1060fe6d75b6e6d558c"

  strings:
    $s1 = "var Li4 = new Array(\"\\x66\",\"\\x75\",\"\\x6e\",\"\\x63\",\"\\x74\",\"\\x69\",\"\\x6f\",\"\\x20\",\"\\x6b\",\"\\x28\",\"\\x29" ascii

  condition:
    uint16(0) == 0x7566 and
    all of them
}