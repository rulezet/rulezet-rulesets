rule _20160921_0f4dee7115fed314f330d52696c0d1d1_20160921_87978dcbc3a2_4369 {
  meta:
    description = "datamaliciousorder - from files 20160921_0f4dee7115fed314f330d52696c0d1d1.js, 20160921_87978dcbc3a23f5dbd5fc73bee04f432.js, 20160921_de03e8e8d98da4b7d17147c979ce9ff8.js, 20160921_e072f9d237d6a3b969fa334b2e277a33.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "dec7336f5db71057e4227c26b20731cd69ad29c7628e161fff2f7964754477b1"
    hash2       = "a6d96c94cf7f327ade629dec6f41b2fcfa7f7accfa8da780df3fea48273270dd"
    hash3       = "aa4eb617dd497a7ea1d016d98ce4ca8e81e13b4e240c42d46d01e84e617a150b"
    hash4       = "6a03793a4e6175c2a80395cdedba1eaf5878722aa36c4cbfae104768ed79890d"

  strings:
    $s1 = "),(function fuck(){return \"IRn\";})(),(function fuck(){return \"OQr\";})(),(function fuck(){return \"Hs\";})(),(function fuck()" ascii
    $s2 = "n \"Wo0\";})(),(function fuck(){return \"ZVi\";})(),(function fuck(){return \"DRx\";})(),(function fuck(){return \"Zy\";})(),(fu" ascii
    $s3 = "function fuck(){return \"QTc\";})(),(function fuck(){return \"DRx\";})(),(function fuck(){return \"XCr\";})(),(function fuck(){r" ascii
    $s4 = "uck(){return \"Sx\";})(),(function fuck(){return \"GNm\";})(),(function fuck(){return \"DRx\";})(),(function fuck(){return \"We" ascii
    $s5 = "k(){return \"ZWu\";})(),(function fuck(){return \"ZLd\";})(),(function fuck(){return \"YAv\";})(),(function fuck(){return \"IPu" ascii

  condition:
    (uint16(0) == 0x2f0a and (all of them)
    ) or (all of them)
}