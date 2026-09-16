rule sig_20160824_6e4641d41a8df0086c97ce7bb46cdaf1 {
  meta:
    description = "datamaliciousorder - file 20160824_6e4641d41a8df0086c97ce7bb46cdaf1.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "2c8716559726fe1f8a0ce8dc64537820e21f0f937acd57911371df04482e0037"

  strings:
    $s1 = "var DOh = new Array(\"\\x66\",\"\\x75\",\"\\x6e\",\"\\x63\",\"\\x74\",\"\\x69\",\"\\x6f\",\"\\x20\",\"\\x6b\",\"\\x28\",\"\\x29" ascii

  condition:
    uint16(0) == 0x7566 and
    all of them
}