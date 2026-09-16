rule sig_20160824_7531927e80c9b9da9b10d76ec6d001c3 {
  meta:
    description = "datamaliciousorder - file 20160824_7531927e80c9b9da9b10d76ec6d001c3.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "b9f9cef96ba7b29504aff4cba55483c36c21209d187836881df7f7ba36b7da4a"

  strings:
    $s1 = "var DOh = new Array(\"\\x66\",\"\\x75\",\"\\x6e\",\"\\x63\",\"\\x74\",\"\\x69\",\"\\x6f\",\"\\x20\",\"\\x6b\",\"\\x28\",\"\\x29" ascii

  condition:
    uint16(0) == 0x7566 and
    all of them
}