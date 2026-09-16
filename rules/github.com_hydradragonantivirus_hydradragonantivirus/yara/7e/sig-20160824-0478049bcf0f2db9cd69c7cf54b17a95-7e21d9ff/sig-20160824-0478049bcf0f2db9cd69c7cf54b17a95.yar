rule sig_20160824_0478049bcf0f2db9cd69c7cf54b17a95 {
  meta:
    description = "datamaliciousorder - file 20160824_0478049bcf0f2db9cd69c7cf54b17a95.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "f8619da2c5db09a22affb70b5799f9c5238dbc21417a97dc5b4aded91d1f135a"

  strings:
    $s1 = "var DOh = new Array(\"\\x66\",\"\\x75\",\"\\x6e\",\"\\x63\",\"\\x74\",\"\\x69\",\"\\x6f\",\"\\x20\",\"\\x6b\",\"\\x28\",\"\\x29" ascii

  condition:
    uint16(0) == 0x7566 and
    all of them
}