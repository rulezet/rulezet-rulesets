rule _20160921_7f682825ca903be9931443996a6639e7_20160921_be4748da0160_3940 {
  meta:
    description = "datamaliciousorder - from files 20160921_7f682825ca903be9931443996a6639e7.js, 20160921_be4748da01602fdf2d9ffd03054028e4.js, 20160921_f156e377f5219607c339e3053fbf1ae8.js, 20160921_f80c41f35464b4c1cc71c3a8431a6e96.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "0702db471409264d1d764fadd3401cdedc4b3ca7166d99d61893fad5007d7f03"
    hash2       = "4847889a558b3e0b60d671ec5082e36330f771c8789f9ae89683bf49e7128616"
    hash3       = "05538f165c9450aa5ee129299544270acb99521d74bac943ca8cf157311609af"
    hash4       = "8186d069d8ec2c8754bba46343500f71eff6d1d47a5ecb2ca82a097bf5b41dc3"

  strings:
    $s1 = "n fuck(){return \"Ai\";})(),(function fuck(){return \"Za\";})(),(function fuck(){return \"IRn\";})(),(function fuck(){return \"I" ascii
    $s2 = "nction fuck(){return \"IPu\";})(),(function fuck(){return \"Vb\";})(),(function fuck(){return \"GNm\";})(),(function fuck(){retu" ascii
    $s3 = "{return \"Na\";})(),(function fuck(){return \"Vb\";})(),(function fuck(){return \"OQr\";})(),(function fuck(){return \"GJx\";})(" ascii
    $s4 = "fuck(){return \"IPu\";})(),(function fuck(){return \"Vb\";})(),(function fuck(){return \"GNm\";})(),(function fuck(){return \"LG" ascii
    $s5 = "rn \"USf\";})(),(function fuck(){return \"GNm\";})(),(function fuck(){return \"IPu\";})(),(function fuck(){return \"Ml\";})(),(f" ascii
    $s6 = "s\";})(),(function fuck(){return \"LGo\";})(),(function fuck(){return \"MBg\";})(),(function fuck(){return \"Ai\";})(),(function" ascii

  condition:
    (uint16(0) == 0x2f0a and (all of them)
    ) or (all of them)
}