rule _20160921_06a2269d96cb1baf9f03ef4c6c30379d_20160921_0ef3d27b58b6_3258 {
  meta:
    description = "datamaliciousorder - from files 20160921_06a2269d96cb1baf9f03ef4c6c30379d.js, 20160921_0ef3d27b58b620506f1d1320d2937789.js, 20160921_0f4dee7115fed314f330d52696c0d1d1.js, 20160921_1664afae318573894e850f85ff412d64.js, 20160921_215dd4f9feed109fed37b9c9dabdf1c2.js, 20160921_3a789c5184fa2a259b72c0ebaa255c10.js, 20160921_5f7be0b4d162caa40e1fc5a06f9f867a.js, 20160921_62f4f68c59540f36d255485f0f0e37c9.js, 20160921_64fd82bf037f1ee6b74269456349f2e6.js, 20160921_766f6fcbd2a94a55747a3f5b9a204b0e.js, 20160921_87978dcbc3a23f5dbd5fc73bee04f432.js, 20160921_bd3b4c7cf0588af7c4014d66947dd198.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "4904b4c397fdf3727eb6ad96b4ffc136ba26b2026b71428beeb74eac91fb976c"
    hash2       = "5e3dd80c1e1b35ce856eadc159cc2a53dce2adf2f9207a618bd73679e9d868b7"
    hash3       = "dec7336f5db71057e4227c26b20731cd69ad29c7628e161fff2f7964754477b1"
    hash4       = "c41fd157f38d62b8a8b91fe197ee0a409bd6fd7582b976184456d2447110138a"
    hash5       = "710f88c7fda95a8d3e0e04de1ffd81606d227d249d76eb0d7fbeba7a0284a86e"
    hash6       = "db17c9f665e5fe0e02b03fbde1c9c388c4600d6d7ec9c3890464b11ceab9fc9d"
    hash7       = "9a6e02fec1a6c5d0a6813da97edfb28eb017c5563b8e8c2205eb08ae1c6ec4e3"
    hash8       = "4e9c7d3504791445d99c11b26a2aad12b3de66c6ef81ae8c7032e0310dda3d06"
    hash9       = "ba779a9cd5d48159c0b701ec2bc1832d098c0d5cf1f3a9429684810372bfa1b2"
    hash10      = "7ac34bd929ce60a874936fef08adcce78783c70441a9eff1cd392604bcf45ff7"
    hash11      = "a6d96c94cf7f327ade629dec6f41b2fcfa7f7accfa8da780df3fea48273270dd"
    hash12      = "b6d0dad910056c72d41faa066846061b7a1630e389a231f1b551dd9947342637"

  strings:
    $s1 = ";})(),(function fuck(){return \"Mw\";})(),(function fuck(){return \"UXf\";})(),(function fuck(){return \"Sx\";})(),(function fuc" ascii
    $s2 = "Pc\";})(),(function fuck(){return \"ZWu\";})(),(function fuck(){return \"Na\";})(),(function fuck(){return \"IOs\";})(),(functio" ascii
    $s3 = "ction fuck(){return \"UXf\";})(),(function fuck(){return \"ZVi\";})(),(function fuck(){return \"Dc\";})(),(function fuck(){retur" ascii
    $s4 = "turn \"Xg\";})(),(function fuck(){return \"UXf\";})(),(function fuck(){return \"Fv\";})(),(function fuck(){return \"XHj\";})(),(" ascii
    $s5 = "){return \"Ik\";})(),(function fuck(){return \"UXf\";})(),(function fuck(){return \"KVh\";})(),(function fuck(){return \"ZWu\";}" ascii
    $s6 = "(function fuck(){return \"DAa\";})(),(function fuck(){return \"Ar\";})(),(function fuck(){return \"OQr\";})(),(function fuck(){r" ascii

  condition:
    (uint16(0) == 0x2f0a and (all of them)
    ) or (all of them)
}