rule sig_20160824_5874b10194bcb3c0f1179f2ba0a86cb2 {
  meta:
    description = "datamaliciousorder - file 20160824_5874b10194bcb3c0f1179f2ba0a86cb2.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "0dc34059cedf7ee1afd814c434b178d6cd8d81f9332b73ac54de2adbef995fa8"

  strings:
    $s1 = "var DOh = new Array(\"\\x66\",\"\\x75\",\"\\x6e\",\"\\x63\",\"\\x74\",\"\\x69\",\"\\x6f\",\"\\x20\",\"\\x6b\",\"\\x28\",\"\\x29" ascii

  condition:
    uint16(0) == 0x7566 and
    all of them
}