rule _20160921_62f4f68c59540f36d255485f0f0e37c9_20160921_8be5b3aac0a2_3851 {
  meta:
    description = "datamaliciousorder - from files 20160921_62f4f68c59540f36d255485f0f0e37c9.js, 20160921_8be5b3aac0a2f47acb168b56c6f880bf.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "4e9c7d3504791445d99c11b26a2aad12b3de66c6ef81ae8c7032e0310dda3d06"
    hash2       = "344d7dd8865545f9f4c1045a85547b4140c66621aeedeb02bf60ff4598ff6930"

  strings:
    $s1 = "ion fuck(){return \"Py\";})(),(function fuck(){return \"DRx\";})(),(function fuck(){return \"Zy\";})(),(function fuck(){return " ascii
    $s2 = "return \"Jh\";})(),(function fuck(){return \"UOe\";})(),(function fuck(){return \"DRx\";})(),(function fuck(){return \"Wo0\";})(" ascii
    $s3 = "n \"Ve\";})(),(function fuck(){return \"Vb\";})(),(function fuck(){return \"IPu\";})(),(function fuck(){return \"DRx\";})(),(fun" ascii
    $s4 = "(),(function fuck(){return \"DRx\";})(),(function fuck(){return \"Zy\";})(),(function fuck(){return \"Jo\";})(),(function fuck()" ascii
    $s5 = "ck(){return \"IPu\";})(),(function fuck(){return \"Hs\";})(),(function fuck(){return \"ZLd\";})(),(function fuck(){return \"Jg\"" ascii
    $s6 = "Et\";})(),(function fuck(){return \"MIl\";})(),(function fuck(){return \"Py\";})(),(function fuck(){return \"MOj\";})(),(functio" ascii

  condition:
    (uint16(0) == 0x2f0a and (all of them)
    ) or (all of them)
}