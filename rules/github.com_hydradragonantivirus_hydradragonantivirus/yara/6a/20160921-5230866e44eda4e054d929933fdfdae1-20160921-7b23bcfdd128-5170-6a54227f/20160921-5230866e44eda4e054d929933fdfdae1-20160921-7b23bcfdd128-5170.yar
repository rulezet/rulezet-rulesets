rule _20160921_5230866e44eda4e054d929933fdfdae1_20160921_7b23bcfdd128_5170 {
  meta:
    description = "datamaliciousorder - from files 20160921_5230866e44eda4e054d929933fdfdae1.js, 20160921_7b23bcfdd1289634cd9a4c73f4cbb144.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "4b11d10d6c2a935fa29f47c13ee54d426aac8d667f3bc2f79681ac7e4d365c76"
    hash2       = "7a94fbc46ac51a544406f9a59bf405cd1e19e8e6681d7feacbc81e5ab7d4a50b"

  strings:
    $s1 = "){return \"IPu\";})(),(function fuck(){return \"RAi\";})(),(function fuck(){return \"USf\";})(),(function fuck(){return \"ADy\";" ascii
    $s2 = "(),(function fuck(){return \"KVh\";})(),(function fuck(){return \"Jo\";})(),(function fuck(){return \"IRn\";})(),(function fuck(" ascii
    $s3 = "Go\";})(),(function fuck(){return \"Hs\";})(),(function fuck(){return \"IPu\";})(),(function fuck(){return \"DRx\";})(),(functio" ascii
    $s4 = "return \"To\";})(),(function fuck(){return \"Ot\";})(),(function fuck(){return \"Jh\";})(),(function fuck(){return \"Jo\";})(),(" ascii
    $s5 = "unction fuck(){return \"MBg\";})(),(function fuck(){return \"Jo\";})(),(function fuck(){return \"LGo\";})(),(function fuck(){ret" ascii

  condition:
    (uint16(0) == 0x2f0a and (all of them)
    ) or (all of them)
}