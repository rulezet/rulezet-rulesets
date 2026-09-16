rule _20160921_511769d99fbe4d59a2e55781fb0eb77c_20160921_766f6fcbd2a9_3772 {
  meta:
    description = "datamaliciousorder - from files 20160921_511769d99fbe4d59a2e55781fb0eb77c.js, 20160921_766f6fcbd2a94a55747a3f5b9a204b0e.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "2f4a69b097fb3d0d29d7f041be11cd2e8af137bd0ed525674079a1b7de28c7fd"
    hash2       = "7ac34bd929ce60a874936fef08adcce78783c70441a9eff1cd392604bcf45ff7"

  strings:
    $s1 = "ion fuck(){return \"Hs\";})(),(function fuck(){return \"Wo0\";})(),(function fuck(){return \"ZVi\";})(),(function fuck(){return " ascii
    $s2 = "),(function fuck(){return \"IPu\";})(),(function fuck(){return \"ZWu\";})(),(function fuck(){return \"ZLd\";})(),(function fuck(" ascii
    $s3 = " fuck(){return \"ZLd\";})(),(function fuck(){return \"Jg\";})(),(function fuck(){return \"GNm\";})(),(function fuck(){return \"M" ascii
    $s4 = "})(),(function fuck(){return \"Zy\";})(),(function fuck(){return \"Sx\";})(),(function fuck(){return \"GNm\";})(),(function fuck" ascii
    $s5 = "urn \"DRx\";})(),(function fuck(){return \"We\";})(),(function fuck(){return \"QTc\";})(),(function fuck(){return \"DRx\";})(),(" ascii
    $s6 = " fuck(){return \"XCr\";})(),(function fuck(){return \"Na\";})(),(function fuck(){return \"IPu\";})(),(function fuck(){return \"D" ascii

  condition:
    (uint16(0) == 0x2f0a and (all of them)
    ) or (all of them)
}