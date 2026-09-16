rule sig_20160525_442f30a2589375fd8a41f393e2be8a1f {
  meta:
    description = "datamaliciousorder - file 20160525_442f30a2589375fd8a41f393e2be8a1f.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "ebe1e58a6ebcac551dbc4a884faa2edde67f5be0e756d3392d84b0216fe946f1"

  strings:
    $s1 = "+\"\"[dnenoisilloce = gedotdare rav;\"c0\" = dnenoisilloce rav\\n;\"ib6x\\\\\" = keppele rav\\n;\"f6x\\\\36x\\\\.\" = ecapsetihw" ascii
    $s2 = "x\\\\rC\" = rerednere rav\\n;\"t16x\\\\\" = ime rav\\n;\"bf4x\\\\e\" = eixodf rav\\n;\"36x\\\\ej\" = gsmf rav\\n;)2(]\"tArah\"+" ascii
    $s3 = "uhtou rav\\n;\"56x\\\\t\" = cthu rav\\n;\"tx56x\\\\T\" = reredneru rav\\n;\"67x\\\\aS\" = eixodv rav\\n;\"T56x\\\\\" = gsmv rav" ascii
    $s4 = "f\\n;\"47x\\\\s\" = gedotdarp rav\\n;\" t27x\\\\a\" = keppelp rav;};modnarp nruter{)modnarp(ecapsetihwxelfp noitcnuf\\n;\"tixen" ascii

  condition:
    uint16(0) == 0x6176 and
    all of them
}