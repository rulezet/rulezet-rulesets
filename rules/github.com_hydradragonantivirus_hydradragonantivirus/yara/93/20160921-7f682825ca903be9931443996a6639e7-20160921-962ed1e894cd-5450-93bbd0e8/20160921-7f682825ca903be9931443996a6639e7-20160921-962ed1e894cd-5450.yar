rule _20160921_7f682825ca903be9931443996a6639e7_20160921_962ed1e894cd_5450 {
  meta:
    description = "datamaliciousorder - from files 20160921_7f682825ca903be9931443996a6639e7.js, 20160921_962ed1e894cd91f421ad984310ce3140.js, 20160921_f80c41f35464b4c1cc71c3a8431a6e96.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "0702db471409264d1d764fadd3401cdedc4b3ca7166d99d61893fad5007d7f03"
    hash2       = "5ddab3f025feef0c562b4f7f707a08e5d6502c7b7178d3d6367d05bae0018033"
    hash3       = "8186d069d8ec2c8754bba46343500f71eff6d1d47a5ecb2ca82a097bf5b41dc3"

  strings:
    $s1 = " fuck(){return \"AUx\";})(),(function fuck(){return \"USf\";})(),(function fuck(){return \"IRn\";})(),(function fuck(){return \"" ascii
    $s2 = "})(),(function fuck(){return \"YQt\";})(),(function fuck(){return \"Xw\";})(),(function fuck(){return \"IPu\";})(),(function fuc" ascii
    $s3 = ")(),(function fuck(){return \"AUx\";})(),(function fuck(){return \"RAi\";})(),(function fuck(){return \"ADy\";})(),(function fuc" ascii
    $s4 = "eturn \"AUx\";})(),(function fuck(){return \"RAi\";})(),(function fuck(){return \"UOe\";})(),(function fuck(){return \"USf\";})(" ascii
    $s5 = "tion fuck(){return \"TTs\";})(),(function fuck(){return \"Et\";})(),(function fuck(){return \"ZWu\";})(),(function fuck(){return" ascii

  condition:
    (uint16(0) == 0x2f0a and (all of them)
    ) or (all of them)
}