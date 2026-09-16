rule sig_20160824_e95b7b0d9a54f02d915de535e3cec074 {
  meta:
    description = "datamaliciousorder - file 20160824_e95b7b0d9a54f02d915de535e3cec074.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "2e95ef7b41f38fa6703fbd47337b575fc2bc81bd56b355f9e5080426b2b33f70"

  strings:
    $s1 = "var DOh = new Array(\"\\x66\",\"\\x75\",\"\\x6e\",\"\\x63\",\"\\x74\",\"\\x69\",\"\\x6f\",\"\\x20\",\"\\x6b\",\"\\x28\",\"\\x29" ascii

  condition:
    uint16(0) == 0x7566 and
    all of them
}