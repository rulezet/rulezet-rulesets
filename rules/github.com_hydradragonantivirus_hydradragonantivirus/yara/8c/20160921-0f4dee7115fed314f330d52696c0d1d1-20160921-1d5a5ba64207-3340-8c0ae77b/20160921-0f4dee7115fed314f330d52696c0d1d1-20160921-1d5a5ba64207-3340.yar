rule _20160921_0f4dee7115fed314f330d52696c0d1d1_20160921_1d5a5ba64207_3340 {
  meta:
    description = "datamaliciousorder - from files 20160921_0f4dee7115fed314f330d52696c0d1d1.js, 20160921_1d5a5ba6420732e8f626755a81334ad4.js, 20160921_5143fd2835d058f3854ef7b166166de4.js, 20160921_87978dcbc3a23f5dbd5fc73bee04f432.js, 20160921_d905978b34bea5948e843dd7ecb9dc6e.js, 20160921_ee6d5c7dc2c03b89ea5ef53aa0c676a1.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "dec7336f5db71057e4227c26b20731cd69ad29c7628e161fff2f7964754477b1"
    hash2       = "47a1fbd3f8785b259468283f9d6611b34da6b0170d66a933ade09c56548f89b4"
    hash3       = "0824c6197846b6efc3bea2626d4bc5983302ec11dd40189770e6572811d3d42c"
    hash4       = "a6d96c94cf7f327ade629dec6f41b2fcfa7f7accfa8da780df3fea48273270dd"
    hash5       = "8110e9072a75f1960f23243cc11d3c233a350d63360d8006cad608a2fb81e0b3"
    hash6       = "ddd3db3929119812b70ad9f62bd3187b6108d24999c41a8ff5390bc9a60387a3"

  strings:
    $s1 = "n \"We\";})(),(function fuck(){return \"Za\";})(),(function fuck(){return \"IPu\";})(),(function fuck(){return \"MBg\";})(),(fun" ascii
    $s2 = "r\";})(),(function fuck(){return \"YQt\";})(),(function fuck(){return \"We\";})(),(function fuck(){return \"ZVi\";})(),(function" ascii
    $s3 = "nction fuck(){return \"IPu\";})(),(function fuck(){return \"Oh\";})(),(function fuck(){return \"Ve\";})(),(function fuck(){retur" ascii
    $s4 = "n fuck(){return \"Oh\";})(),(function fuck(){return \"XFd\";})(),(function fuck(){return \"Xg\";})(),(function fuck(){return \"M" ascii
    $s5 = "turn \"Za\";})(),(function fuck(){return \"IRn\";})(),(function fuck(){return \"OPz\";})(),(function fuck(){return \"IPu\";})()," ascii
    $s6 = "{return \"Np\";})(),(function fuck(){return \"TTs\";})(),(function fuck(){return \"Nm\";})(),(function fuck(){return \"DWe\";})(" ascii

  condition:
    (uint16(0) == 0x2f0a and (all of them)
    ) or (all of them)
}