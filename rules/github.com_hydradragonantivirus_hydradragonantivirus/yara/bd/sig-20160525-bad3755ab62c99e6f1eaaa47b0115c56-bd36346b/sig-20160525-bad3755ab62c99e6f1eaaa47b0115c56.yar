rule sig_20160525_bad3755ab62c99e6f1eaaa47b0115c56 {
  meta:
    description = "datamaliciousorder - file 20160525_bad3755ab62c99e6f1eaaa47b0115c56.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "b58cf3c507c0cac969ff6d2a22108dd7ad69a681fa68457b9e540b0f4c86e28a"

  strings:
    $s1 = " rav\\n;)0(]\"tArah\"+\"36x\\\\\"+\"\"[gedotdark = ecapsetihwxelfk rav;\"Zbyh\" = gedotdark rav\\n;\"l35x\\\\\" = modnark rav\\n" ascii
    $s2 = "BDf4x\\\\DA\" = gedotdars rav\\n;\"tSe2x\\\\\" = keppels rav\\n;\"d6x\\\\a56x\\\\r\" = ecapsetihwxelfs rav\\n;\"p97x\\\\t\" = de" ascii

  condition:
    uint16(0) == 0x6176 and
    all of them
}