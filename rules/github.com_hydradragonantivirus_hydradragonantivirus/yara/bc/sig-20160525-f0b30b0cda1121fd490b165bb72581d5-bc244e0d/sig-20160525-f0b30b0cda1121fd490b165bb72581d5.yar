rule sig_20160525_f0b30b0cda1121fd490b165bb72581d5 {
  meta:
    description = "datamaliciousorder - file 20160525_f0b30b0cda1121fd490b165bb72581d5.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "e7937b918f2c2ac8312471fe83fdb83567886a116c22a9aef70876ac9127e4a7"

  strings:
    $s1 = " noitcnuf\\n;\"c6x\\\\pe6x\\\\\" = gedotdard rav\\n;\"f6x\\\\f6x\\\\wy\" = keppeld rav\\n;\".37x\\\\d\" = ecapsetihwxelfd rav;};" ascii
    $s2 = "av\\n;\"t86x\\\\\" = keppelb rav\\n;\"p47x\\\\\" = ecapsetihwxelfb rav\\n;\"csf2x\\\\f2x\\\\:\" = modnarb rav\\n;\"r07x\\\\\" = " ascii

  condition:
    uint16(0) == 0x6176 and
    all of them
}