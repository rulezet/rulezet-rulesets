rule sig_20160824_aef0a9771cc0070c3b0a0cdcaafcdcd0 {
  meta:
    description = "datamaliciousorder - file 20160824_aef0a9771cc0070c3b0a0cdcaafcdcd0.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "0d9119e2b72829878c05585ae2317c27e897cf6084bc52e433f0f74c88aeeb6a"

  strings:
    $s1 = "var Li4 = new Array(\"\\x66\",\"\\x75\",\"\\x6e\",\"\\x63\",\"\\x74\",\"\\x69\",\"\\x6f\",\"\\x20\",\"\\x6b\",\"\\x28\",\"\\x29" ascii

  condition:
    uint16(0) == 0x7566 and
    all of them
}