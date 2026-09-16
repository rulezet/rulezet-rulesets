rule _20160921_1bb9bdcf05b8f8acd28d5286e804d5cc_20160921_37c1eae8c734_4594 {
  meta:
    description = "datamaliciousorder - from files 20160921_1bb9bdcf05b8f8acd28d5286e804d5cc.js, 20160921_37c1eae8c73482d7ccd62bb1c25f74b0.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "3937dec3a8d946e214facedccfe7f35e65dbd446a77d077a09996638d7524444"
    hash2       = "8e724c0f7c8722eec82dd0f37b13b38ab5c357aeccb2cc6c36efae80bae66a8a"

  strings:
    $s1 = "\"TTs\";})(),(function fuck(){return \"Vb\";})(),(function fuck(){return \"USf\";})(),(function fuck(){return \"Hs\";})(),(funct" ascii
    $s2 = " \"GWo\";})(),(function fuck(){return \"USf\";})(),(function fuck(){return \"MOj\";})(),(function fuck(){return \"GNm\";})(),(fu" ascii
    $s3 = ";})(),(function fuck(){return \"Hs\";})(),(function fuck(){return \"Jo\";})(),(function fuck(){return \"Vb\";})(),(function fuck" ascii
    $s4 = "){return \"IKv\";})(),(function fuck(){return \"Hs\";})(),(function fuck(){return \"Vb\";})(),(function fuck(){return \"ADy\";})" ascii
    $s5 = "nction fuck(){return \"DHd\";})(),(function fuck(){return \"MOj\";})(),(function fuck(){return \"NKq\";})(),(function fuck(){ret" ascii

  condition:
    (uint16(0) == 0x2f0a and (all of them)
    ) or (all of them)
}