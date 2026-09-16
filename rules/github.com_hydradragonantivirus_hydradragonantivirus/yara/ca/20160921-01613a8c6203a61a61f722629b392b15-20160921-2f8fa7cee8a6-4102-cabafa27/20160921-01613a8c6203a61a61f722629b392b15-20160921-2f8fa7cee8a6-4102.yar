rule _20160921_01613a8c6203a61a61f722629b392b15_20160921_2f8fa7cee8a6_4102 {
  meta:
    description = "datamaliciousorder - from files 20160921_01613a8c6203a61a61f722629b392b15.js, 20160921_2f8fa7cee8a6f4f78978b7417f3f700e.js, 20160921_d03dc2f478ae343430b4a6dbcc9d6c08.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "7c3ee763f1740e8bc6ded9772aabbe3d3805d8cf2a023e0289a9b8a1a42624b7"
    hash2       = "6410122a95cd840a4eef622389d8026475b4f6a156d4b5288cf227165c036c96"
    hash3       = "dd1077874fb7f556e5acfe2ff0c2ed6b6c203fcdf442119ca307096446d90cd4"

  strings:
    $s1 = ",(function fuck(){return \"XCr\";})(),(function fuck(){return \"ZVi\";})(),(function fuck(){return \"Np\";})(),(function fuck(){" ascii
    $s2 = "urn \"MUs\";})(),(function fuck(){return \"KVh\";})(),(function fuck(){return \"Xw\";})(),(function fuck(){return \"IPu\";})(),(" ascii
    $s3 = "on fuck(){return \"UOe\";})(),(function fuck(){return \"Np\";})(),(function fuck(){return \"IPu\";})(),(function fuck(){return " ascii
    $s4 = "ck(){return \"MIl\";})(),(function fuck(){return \"FJs\";})(),(function fuck(){return \"ADy\";})(),(function fuck(){return \"DRx" ascii
    $s5 = "fuck(){return \"Jg\";})(),(function fuck(){return \"RAi\";})(),(function fuck(){return \"DRx\";})(),(function fuck(){return \"MI" ascii

  condition:
    (uint16(0) == 0x2f0a and (all of them)
    ) or (all of them)
}