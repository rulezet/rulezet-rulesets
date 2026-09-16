rule _20160921_1bb9bdcf05b8f8acd28d5286e804d5cc_20160921_de770f0ed114_4593 {
  meta:
    description = "datamaliciousorder - from files 20160921_1bb9bdcf05b8f8acd28d5286e804d5cc.js, 20160921_de770f0ed114194a1a9d5e965c4fe675.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "3937dec3a8d946e214facedccfe7f35e65dbd446a77d077a09996638d7524444"
    hash2       = "57a3f4ba7362a09dfecfe27f6b8517c8290bc04a7020f4bbe4e9200a42655be0"

  strings:
    $s1 = "(function fuck(){return \"Yk\";})(),(function fuck(){return \"FJs\";})(),(function fuck(){return \"IPu\";})(),(function fuck(){r" ascii
    $s2 = ")(),(function fuck(){return \"Jg\";})(),(function fuck(){return \"Hs\";})(),(function fuck(){return \"IPu\";})(),(function fuck(" ascii
    $s3 = "ion fuck(){return \"IOs\";})(),(function fuck(){return \"Fv\";})(),(function fuck(){return \"TTs\";})(),(function fuck(){return " ascii
    $s4 = "k(){return \"IOs\";})(),(function fuck(){return \"LGo\";})(),(function fuck(){return \"IRn\";})(),(function fuck(){return \"OQr" ascii
    $s5 = "rn \"DRx\";})(),(function fuck(){return \"IPu\";})(),(function fuck(){return \"Et\";})(),(function fuck(){return \"Oh\";})(),(fu" ascii

  condition:
    (uint16(0) == 0x2f0a and (all of them)
    ) or (all of them)
}