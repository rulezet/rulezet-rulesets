rule _20160921_207d0a8168d3fb16019724b9f72c41ba_20160921_d7a1651fca71_4659 {
  meta:
    description = "datamaliciousorder - from files 20160921_207d0a8168d3fb16019724b9f72c41ba.js, 20160921_d7a1651fca7129364bbe9da7195a89dc.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "90b56af8225bf5087b8c8ea31ab85a80e0951c3a32b8a0a0be7e09ef2efc8172"
    hash2       = "2c37b7e410e05a2e285f2d4909012cdefffdcc0d9e06b06aafce7aba5b9684f6"

  strings:
    $s1 = "k(){return \"Cd\";})(),(function fuck(){return \"To\";})(),(function fuck(){return \"Fv\";})(),(function fuck(){return \"ADy\";}" ascii
    $s2 = ";})(),(function fuck(){return \"DWe\";})(),(function fuck(){return \"ZLd\";})(),(function fuck(){return \"Dc\";})(),(function fu" ascii
    $s3 = "\";})(),(function fuck(){return \"FJs\";})(),(function fuck(){return \"Py\";})(),(function fuck(){return \"IPu\";})(),(function " ascii
    $s4 = " fuck(){return \"Za\";})(),(function fuck(){return \"Py\";})(),(function fuck(){return \"IPu\";})(),(function fuck(){return \"DR" ascii
    $s5 = "return \"DRx\";})(),(function fuck(){return \"IPu\";})(),(function fuck(){return \"PDf\";})(),(function fuck(){return \"DWe\";})" ascii

  condition:
    (uint16(0) == 0x2f0a and (all of them)
    ) or (all of them)
}