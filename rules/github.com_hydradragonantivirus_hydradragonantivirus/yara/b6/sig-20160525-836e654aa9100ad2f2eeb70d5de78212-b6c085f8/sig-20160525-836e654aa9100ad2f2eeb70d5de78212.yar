rule sig_20160525_836e654aa9100ad2f2eeb70d5de78212 {
  meta:
    description = "datamaliciousorder - file 20160525_836e654aa9100ad2f2eeb70d5de78212.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "fba70b99d426c3d2c62942377289257e2a1940003e88ba351da8b5f4aa5ba5df"

  strings:
    $s1 = "dare rav\\n;\"13x\\\\/t\" = keppele rav\\n;\"47x\\\\c\" = ecapsetihwxelfe rav\\n;\"a6x\\\\h\" = sdnete rav\\n;)1(]\"tAra\"+\"86x" ascii

  condition:
    uint16(0) == 0x200a and
    all of them
}