rule _20160921_30902cdec8afbffc64d0c0cd57e17570_20160921_c58f55b02ed5_3592 {
  meta:
    description = "datamaliciousorder - from files 20160921_30902cdec8afbffc64d0c0cd57e17570.js, 20160921_c58f55b02ed5bcc68d14314fe1cbe1f0.js, 20160921_de03e8e8d98da4b7d17147c979ce9ff8.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "794f51b8ce9ffbf2858ed5522e027d4ca3155be961907d88f09dd5679b3f1a18"
    hash2       = "9b14dd6c2f6263aca7c445e6160fdf64ae8e12248f26b67576668dd3b4f18382"
    hash3       = "aa4eb617dd497a7ea1d016d98ce4ca8e81e13b4e240c42d46d01e84e617a150b"

  strings:
    $s1 = "ction fuck(){return \"DRx\";})(),(function fuck(){return \"IPu\";})(),(function fuck(){return \"DWe\";})(),(function fuck(){retu" ascii
    $s2 = "){return \"IPu\";})(),(function fuck(){return \"Nm\";})(),(function fuck(){return \"FJs\";})(),(function fuck(){return \"IPu\";}" ascii
    $s3 = "Zy\";})(),(function fuck(){return \"Jg\";})(),(function fuck(){return \"IPu\";})(),(function fuck(){return \"DRx\";})(),(functio" ascii
    $s4 = "ction fuck(){return \"DRx\";})(),(function fuck(){return \"IPu\";})(),(function fuck(){return \"ZLd\";})(),(function fuck(){retu" ascii
    $s5 = "n \"Ar\";})(),(function fuck(){return \"IRn\";})(),(function fuck(){return \"OQr\";})(),(function fuck(){return \"Et\";})(),(fun" ascii
    $s6 = "s\";})(),(function fuck(){return \"PDf\";})(),(function fuck(){return \"IPu\";})(),(function fuck(){return \"DRx\";})(),(functio" ascii

  condition:
    (uint16(0) == 0x2f0a and (all of them)
    ) or (all of them)
}