rule sig_20160525_e7568835bddbc73374107ce2020ae3ce {
  meta:
    description = "datamaliciousorder - file 20160525_e7568835bddbc73374107ce2020ae3ce.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "e846a52e1ed948db4d93d2ee4a990e6d9d5c21d47a5985233b58bec2bdb793cf"

  strings:
    $s1 = " noitcnuf\\n;\"pf6x\\\\\" = cthi rav\\n;\"e6x\\\\e\" = reredneri rav;};mj nruter{)mj(dnenoisillocj noitcnuf;};suidarelcitrapj nr" ascii
    $s2 = "43x\\\\\" = gedotdarb rav\\n;\"t86x\\\\\" = keppelb rav\\n;\"p47x\\\\\" = ecapsetihwxelfb rav\\n;\"f2x\\\\f2x\\\\:\" = modnarb r" ascii

  condition:
    uint16(0) == 0x6176 and
    all of them
}