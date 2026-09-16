rule sig_20160824_26a27c3268aa09eba45ffde1c0d52915 {
  meta:
    description = "datamaliciousorder - file 20160824_26a27c3268aa09eba45ffde1c0d52915.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "e7143a50f0bf9be77e0ac52a8688b69e7a11a48be293a389c85e7f2963337008"

  strings:
    $s1 = "var DOh = new Array(\"\\x66\",\"\\x75\",\"\\x6e\",\"\\x63\",\"\\x74\",\"\\x69\",\"\\x6f\",\"\\x20\",\"\\x6b\",\"\\x28\",\"\\x29" ascii

  condition:
    uint16(0) == 0x7566 and
    all of them
}