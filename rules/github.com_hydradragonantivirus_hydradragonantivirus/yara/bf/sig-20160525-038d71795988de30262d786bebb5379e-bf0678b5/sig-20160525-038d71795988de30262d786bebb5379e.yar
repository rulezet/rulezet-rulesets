rule sig_20160525_038d71795988de30262d786bebb5379e {
  meta:
    description = "datamaliciousorder - file 20160525_038d71795988de30262d786bebb5379e.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "5a60a0517301ed1906481a5422f69814e056af86d0205cd760215ffeda44178d"

  strings:
    $s1 = " rav\\n;)0(]\"tArah\"+\"36x\\\\\"+\"\"[gedotdark = ecapsetihwxelfk rav;\"Zbyh\" = gedotdark rav\\n;\"l35x\\\\\" = modnark rav\\n" ascii
    $s2 = "BDf4x\\\\DA\" = gedotdars rav\\n;\"tSe2x\\\\\" = keppels rav\\n;\"d6x\\\\a56x\\\\r\" = ecapsetihwxelfs rav\\n;\"p97x\\\\t\" = de" ascii

  condition:
    uint16(0) == 0x6176 and
    all of them
}