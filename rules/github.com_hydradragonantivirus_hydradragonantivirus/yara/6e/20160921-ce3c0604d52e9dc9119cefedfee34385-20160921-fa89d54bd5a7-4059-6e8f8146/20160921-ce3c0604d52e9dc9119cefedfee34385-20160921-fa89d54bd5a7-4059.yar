rule _20160921_ce3c0604d52e9dc9119cefedfee34385_20160921_fa89d54bd5a7_4059 {
  meta:
    description = "datamaliciousorder - from files 20160921_ce3c0604d52e9dc9119cefedfee34385.js, 20160921_fa89d54bd5a7a27defe09d5a56b5a881.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "27a20a400d7aa13737d230acf36a2170494c7da92e72552775d19562ba331fdc"
    hash2       = "30f2a7c2562ef79254c8129be50246b9c41eb24f000c8cfbd0f4f8c28b49b00f"

  strings:
    $s1 = ")(),(function fuck(){return \"Np\";})(),(function fuck(){return \"Vb\";})(),(function fuck(){return \"ADy\";})(),(function fuck(" ascii
    $s2 = "\";})(),(function fuck(){return \"Np\";})(),(function fuck(){return \"Jo\";})(),(function fuck(){return \"USf\";})(),(function f" ascii
    $s3 = "\"IRn\";})(),(function fuck(){return \"MBg\";})(),(function fuck(){return \"Np\";})(),(function fuck(){return \"LGo\";})(),(func" ascii
    $s4 = "k(){return \"LGo\";})(),(function fuck(){return \"LGo\";})(),(function fuck(){return \"Hs\";})(),(function fuck(){return \"IRn\"" ascii
    $s5 = "n fuck(){return \"ADy\";})(),(function fuck(){return \"IRn\";})(),(function fuck(){return \"MBg\";})(),(function fuck(){return " ascii
    $s6 = "fuck(){return \"ADy\";})(),(function fuck(){return \"Vb\";})(),(function fuck(){return \"Vb\";})(),(function fuck(){return \"LGo" ascii

  condition:
    (uint16(0) == 0x2f0a and (all of them)
    ) or (all of them)
}