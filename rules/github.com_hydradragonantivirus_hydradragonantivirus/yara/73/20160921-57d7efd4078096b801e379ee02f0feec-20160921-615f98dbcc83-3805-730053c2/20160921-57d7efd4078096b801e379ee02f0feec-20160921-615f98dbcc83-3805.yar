rule _20160921_57d7efd4078096b801e379ee02f0feec_20160921_615f98dbcc83_3805 {
  meta:
    description = "datamaliciousorder - from files 20160921_57d7efd4078096b801e379ee02f0feec.js, 20160921_615f98dbcc83e57c9789ba9d89e188d0.js, 20160921_b04f9fe7316d0e86c0046e130e905e37.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "e568760a55d343665c530313749711c3424bfd35c792b1a8b1d5ad6fa004c9a6"
    hash2       = "3ee4da5f56533720f6cb24f55125aadc635f7464c5c8a7fbc14e3949f44d0ee5"
    hash3       = "58df336ac7568c9f52fedec5d0b900480491f3e65f56c23426010ec745a6bddd"

  strings:
    $s1 = "ction fuck(){return \"TTs\";})(),(function fuck(){return \"To\";})(),(function fuck(){return \"UXf\";})(),(function fuck(){retur" ascii
    $s2 = "function fuck(){return \"GNm\";})(),(function fuck(){return \"Cd\";})(),(function fuck(){return \"NKq\";})(),(function fuck(){re" ascii
    $s3 = "ion fuck(){return \"DRx\";})(),(function fuck(){return \"IPu\";})(),(function fuck(){return \"CCb\";})(),(function fuck(){return" ascii
    $s4 = "eturn \"IPu\";})(),(function fuck(){return \"Hs\";})(),(function fuck(){return \"MUs\";})(),(function fuck(){return \"GNm\";})()" ascii
    $s5 = "(function fuck(){return \"IPu\";})(),(function fuck(){return \"Qh\";})(),(function fuck(){return \"ZVi\";})(),(function fuck(){r" ascii
    $s6 = "{return \"Vf\";})(),(function fuck(){return \"XCr\";})(),(function fuck(){return \"Jh\";})(),(function fuck(){return \"IPu\";})(" ascii

  condition:
    (uint16(0) == 0x2f0a and (all of them)
    ) or (all of them)
}