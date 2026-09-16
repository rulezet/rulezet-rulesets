rule _20160921_7b23bcfdd1289634cd9a4c73f4cbb144_20160921_7f682825ca90_3924 {
  meta:
    description = "datamaliciousorder - from files 20160921_7b23bcfdd1289634cd9a4c73f4cbb144.js, 20160921_7f682825ca903be9931443996a6639e7.js, 20160921_f80c41f35464b4c1cc71c3a8431a6e96.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "7a94fbc46ac51a544406f9a59bf405cd1e19e8e6681d7feacbc81e5ab7d4a50b"
    hash2       = "0702db471409264d1d764fadd3401cdedc4b3ca7166d99d61893fad5007d7f03"
    hash3       = "8186d069d8ec2c8754bba46343500f71eff6d1d47a5ecb2ca82a097bf5b41dc3"

  strings:
    $s1 = "ction fuck(){return \"IPu\";})(),(function fuck(){return \"Np\";})(),(function fuck(){return \"UOe\";})(),(function fuck(){retur" ascii
    $s2 = " fuck(){return \"Vb\";})(),(function fuck(){return \"ADy\";})(),(function fuck(){return \"Vb\";})(),(function fuck(){return \"IP" ascii
    $s3 = ")(),(function fuck(){return \"UOe\";})(),(function fuck(){return \"Vb\";})(),(function fuck(){return \"Np\";})(),(function fuck(" ascii
    $s4 = "Ai\";})(),(function fuck(){return \"TTs\";})(),(function fuck(){return \"Np\";})(),(function fuck(){return \"ADy\";})(),(functio" ascii
    $s5 = "urn \"IRn\";})(),(function fuck(){return \"MBg\";})(),(function fuck(){return \"IKv\";})(),(function fuck(){return \"Np\";})(),(" ascii
    $s6 = "n \"Vb\";})(),(function fuck(){return \"Vb\";})(),(function fuck(){return \"LGo\";})(),(function fuck(){return \"NKq\";})(),(fun" ascii

  condition:
    (uint16(0) == 0x2f0a and (all of them)
    ) or (all of them)
}