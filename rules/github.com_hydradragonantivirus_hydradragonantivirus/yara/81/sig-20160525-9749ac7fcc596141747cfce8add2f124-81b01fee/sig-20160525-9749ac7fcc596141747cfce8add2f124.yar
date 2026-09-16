rule sig_20160525_9749ac7fcc596141747cfce8add2f124 {
  meta:
    description = "datamaliciousorder - file 20160525_9749ac7fcc596141747cfce8add2f124.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "7b3ebbcebd98858706c4b49e4d3b2163975a0dae5fc311ef92c876092eaa1fb0"

  strings:
    $s1 = "dark noitcnuf( + eixodk + ))(};imj nruter{)(mk noitcnuf( + rerednerj(]ime + rerednere + cthe[tpircSW = eixodb rav    \\n{\\n)sso" ascii
    $s2 = "c6x\\\\\" = imq rav\\n;)2(]\"tArah\"+\"36x\\\\\"+\"\"[rerednerq = eixodr rav;\"h3K\" = rerednerq rav\\n;\"e6x\\\\el\" = gsmr rav" ascii

  condition:
    uint16(0) == 0x6176 and
    all of them
}