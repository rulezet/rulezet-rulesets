rule sig_20160824_a9754f3b04202ac1db57989fe8dd2046 {
  meta:
    description = "datamaliciousorder - file 20160824_a9754f3b04202ac1db57989fe8dd2046.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "9e5135ad17967651724d204c529523f17e410f126081c0615b9d4f5e26cd682d"

  strings:
    $s1 = "var DOh = new Array(\"\\x66\",\"\\x75\",\"\\x6e\",\"\\x63\",\"\\x74\",\"\\x69\",\"\\x6f\",\"\\x20\",\"\\x6b\",\"\\x28\",\"\\x29" ascii

  condition:
    uint16(0) == 0x7566 and
    all of them
}