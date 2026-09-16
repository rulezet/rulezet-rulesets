rule _20160921_7f682825ca903be9931443996a6639e7_20160921_ef5539a74fa9_3060 {
  meta:
    description = "datamaliciousorder - from files 20160921_7f682825ca903be9931443996a6639e7.js, 20160921_ef5539a74fa92cc432f92987e238b0be.js, 20160921_f80c41f35464b4c1cc71c3a8431a6e96.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "0702db471409264d1d764fadd3401cdedc4b3ca7166d99d61893fad5007d7f03"
    hash2       = "6a7080b4743207e49b99932d406b2ee18d652ac2222bdb5a88a66af8dea13c80"
    hash3       = "8186d069d8ec2c8754bba46343500f71eff6d1d47a5ecb2ca82a097bf5b41dc3"

  strings:
    $s1 = "return \"MIl\";})(),(function fuck(){return \"Sx\";})(),(function fuck(){return \"DRx\";})(),(function fuck(){return \"ZLd\";})(" ascii
    $s2 = ")(),(function fuck(){return \"CCb\";})(),(function fuck(){return \"Mw\";})(),(function fuck(){return \"Np\";})(),(function fuck(" ascii
    $s3 = "urn \"MBg\";})(),(function fuck(){return \"LGo\";})(),(function fuck(){return \"YQt\";})(),(function fuck(){return \"AUx\";})()," ascii
    $s4 = "n \"DRx\";})(),(function fuck(){return \"IPu\";})(),(function fuck(){return \"Ai\";})(),(function fuck(){return \"MIl\";})(),(fu" ascii
    $s5 = "uck(){return \"KVh\";})(),(function fuck(){return \"YQt\";})(),(function fuck(){return \"IPu\";})(),(function fuck(){return \"DR" ascii
    $s6 = "ion fuck(){return \"Ot\";})(),(function fuck(){return \"Sx\";})(),(function fuck(){return \"ADy\";})(),(function fuck(){return " ascii
    $s7 = "rn \"DRx\";})(),(function fuck(){return \"Zy\";})(),(function fuck(){return \"MUs\";})(),(function fuck(){return \"IPu\";})(),(f" ascii

  condition:
    (uint16(0) == 0x2f0a and (all of them)
    ) or (all of them)
}