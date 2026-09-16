rule _20160921_469953d9833167e141d9f086f1f41437_20160921_f575ae0885e7_5071 {
  meta:
    description = "datamaliciousorder - from files 20160921_469953d9833167e141d9f086f1f41437.js, 20160921_f575ae0885e764a3ea3a621283d492e2.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "e29808d818b8f5ea60d0baa8d6c3284d3673878f7f4309c5981ced86dc40c5f1"
    hash2       = "56a063ba0d781a52d612f976f937d59e64bb8200cf3c4b448f3cb3013733bdaf"

  strings:
    $s1 = "ck(){return \"DRx\";})(),(function fuck(){return \"IPu\";})(),(function fuck(){return \"LGo\";})(),(function fuck(){return \"YQt" ascii
    $s2 = "tion fuck(){return \"CTm\";})(),(function fuck(){return \"CTm\";})(),(function fuck(){return \"We\";})(),(function fuck(){return" ascii
    $s3 = "urn \"DRx\";})(),(function fuck(){return \"IPu\";})(),(function fuck(){return \"Ot\";})(),(function fuck(){return \"Ik\";})(),(f" ascii
    $s4 = "),(function fuck(){return \"YQt\";})(),(function fuck(){return \"IPu\";})(),(function fuck(){return \"MBg\";})(),(function fuck(" ascii
    $s5 = "})(),(function fuck(){return \"Ve\";})(),(function fuck(){return \"Ar\";})(),(function fuck(){return \"IPu\";})(),(function fuck" ascii

  condition:
    (uint16(0) == 0x2f0a and (all of them)
    ) or (all of them)
}