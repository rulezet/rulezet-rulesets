rule sig_20160824_9a38a9671dff0d8d287486f364abd152 {
  meta:
    description = "datamaliciousorder - file 20160824_9a38a9671dff0d8d287486f364abd152.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "4b9097a5c5481a8b4a75488fea0e67ec23e9361de6f40171e1423ff558bcb72f"

  strings:
    $s1 = "var Li4 = new Array(\"\\x66\",\"\\x75\",\"\\x6e\",\"\\x63\",\"\\x74\",\"\\x69\",\"\\x6f\",\"\\x20\",\"\\x6b\",\"\\x28\",\"\\x29" ascii

  condition:
    uint16(0) == 0x7566 and
    all of them
}