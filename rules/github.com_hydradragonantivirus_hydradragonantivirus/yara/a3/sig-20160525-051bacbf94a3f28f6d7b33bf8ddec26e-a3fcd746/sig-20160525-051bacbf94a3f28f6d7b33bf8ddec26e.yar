rule sig_20160525_051bacbf94a3f28f6d7b33bf8ddec26e {
  meta:
    description = "datamaliciousorder - file 20160525_051bacbf94a3f28f6d7b33bf8ddec26e.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "ef66448128f41f36642b28c46c30de7a09e74669df0a99f84bc0619d15d8b991"

  strings:
    $s1 = "cb = modnar rav\\n;)eixodh + img + rerednerg + cthg(]keppelg + gedotdarg + mg + dnenoisillocg[tpircSW = dnenoisillocb rav\\n;]su" ascii
    $s2 = " = gedotdars rav;};ecapsetihwxelfs nruter{)ecapsetihwxelfs(keppels noitcnuf\\n;\"16x\\\\e25x\\\\\" = modnars rav\\n;\"56x\\\\T46" ascii

  condition:
    uint16(0) == 0x200a and
    all of them
}