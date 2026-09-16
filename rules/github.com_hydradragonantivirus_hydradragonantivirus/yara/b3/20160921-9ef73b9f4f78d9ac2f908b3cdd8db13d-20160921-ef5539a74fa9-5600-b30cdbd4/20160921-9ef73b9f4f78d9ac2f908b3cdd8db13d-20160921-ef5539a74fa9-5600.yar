rule _20160921_9ef73b9f4f78d9ac2f908b3cdd8db13d_20160921_ef5539a74fa9_5600 {
  meta:
    description = "datamaliciousorder - from files 20160921_9ef73b9f4f78d9ac2f908b3cdd8db13d.js, 20160921_ef5539a74fa92cc432f92987e238b0be.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "31bd1528e102f576486e80b1ead7224fc04db7a81b4fbf1ae11c4416b5e4bd57"
    hash2       = "6a7080b4743207e49b99932d406b2ee18d652ac2222bdb5a88a66af8dea13c80"

  strings:
    $s1 = "n fuck(){return \"MUs\";})(),(function fuck(){return \"IPu\";})(),(function fuck(){return \"OQr\";})(),(function fuck(){return " ascii
    $s2 = "){return \"Na\";})(),(function fuck(){return \"Vb\";})(),(function fuck(){return \"OQr\";})(),(function fuck(){return \"GJx\";})" ascii
    $s3 = "urn \"USf\";})(),(function fuck(){return \"GNm\";})(),(function fuck(){return \"IPu\";})(),(function fuck(){return \"Ml\";})(),(" ascii
    $s4 = "Us\";})(),(function fuck(){return \"LGo\";})(),(function fuck(){return \"MBg\";})(),(function fuck(){return \"Ai\";})(),(functio" ascii
    $s5 = "turn \"CTm\";})(),(function fuck(){return \"CTm\";})(),(function fuck(){return \"CTm\";})(),(function fuck(){return \"Dc\";})()," ascii

  condition:
    (uint16(0) == 0x2f0a and (all of them)
    ) or (all of them)
}