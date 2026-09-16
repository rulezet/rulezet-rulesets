rule sig_20160525_2e0110a0a59dbe278552169ba86c2dd2 {
  meta:
    description = "datamaliciousorder - file 20160525_2e0110a0a59dbe278552169ba86c2dd2.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "653ce3391be492332edeb27618cdb57c5df789f9728529faec100abbd2ea2b83"

  strings:
    $s1 = " noitcnuf\\n;\"pf6x\\\\\" = cthi rav\\n;\"e6x\\\\e\" = reredneri rav;};mj nruter{)mj(dnenoisillocj noitcnuf;};suidarelcitrapj nr" ascii
    $s2 = "43x\\\\\" = gedotdarb rav\\n;\"t86x\\\\\" = keppelb rav\\n;\"p47x\\\\\" = ecapsetihwxelfb rav\\n;\"f2x\\\\f2x\\\\:\" = modnarb r" ascii

  condition:
    uint16(0) == 0x6176 and
    all of them
}