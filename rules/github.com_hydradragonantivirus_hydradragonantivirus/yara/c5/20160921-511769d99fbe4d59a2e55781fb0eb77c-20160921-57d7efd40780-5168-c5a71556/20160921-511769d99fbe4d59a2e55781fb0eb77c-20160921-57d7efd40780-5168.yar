rule _20160921_511769d99fbe4d59a2e55781fb0eb77c_20160921_57d7efd40780_5168 {
  meta:
    description = "datamaliciousorder - from files 20160921_511769d99fbe4d59a2e55781fb0eb77c.js, 20160921_57d7efd4078096b801e379ee02f0feec.js, 20160921_b04f9fe7316d0e86c0046e130e905e37.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "2f4a69b097fb3d0d29d7f041be11cd2e8af137bd0ed525674079a1b7de28c7fd"
    hash2       = "e568760a55d343665c530313749711c3424bfd35c792b1a8b1d5ad6fa004c9a6"
    hash3       = "58df336ac7568c9f52fedec5d0b900480491f3e65f56c23426010ec745a6bddd"

  strings:
    $s1 = "a\";})(),(function fuck(){return \"IPu\";})(),(function fuck(){return \"Oh\";})(),(function fuck(){return \"Ve\";})(),(function " ascii
    $s2 = "nction fuck(){return \"MBg\";})(),(function fuck(){return \"IPu\";})(),(function fuck(){return \"ZWu\";})(),(function fuck(){ret" ascii
    $s3 = " fuck(){return \"Ml\";})(),(function fuck(){return \"IPu\";})(),(function fuck(){return \"LGo\";})(),(function fuck(){return \"P" ascii
    $s4 = "unction fuck(){return \"XFd\";})(),(function fuck(){return \"Xg\";})(),(function fuck(){return \"TTs\";})(),(function fuck(){ret" ascii
    $s5 = "turn \"XFd\";})(),(function fuck(){return \"Xg\";})(),(function fuck(){return \"IPu\";})(),(function fuck(){return \"MBg\";})()," ascii

  condition:
    (uint16(0) == 0x2f0a and (all of them)
    ) or (all of them)
}