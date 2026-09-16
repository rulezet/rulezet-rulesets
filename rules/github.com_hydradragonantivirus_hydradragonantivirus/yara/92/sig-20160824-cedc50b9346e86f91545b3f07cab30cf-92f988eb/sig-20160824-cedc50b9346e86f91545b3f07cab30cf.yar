rule sig_20160824_cedc50b9346e86f91545b3f07cab30cf {
  meta:
    description = "datamaliciousorder - file 20160824_cedc50b9346e86f91545b3f07cab30cf.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "1dbb8870345d091061d8e1ba8a7659ae772dff3edf62f14fbf4245eab78256b1"

  strings:
    $s1 = "var DOh = new Array(\"\\x66\",\"\\x75\",\"\\x6e\",\"\\x63\",\"\\x74\",\"\\x69\",\"\\x6f\",\"\\x20\",\"\\x6b\",\"\\x28\",\"\\x29" ascii

  condition:
    uint16(0) == 0x7566 and
    all of them
}