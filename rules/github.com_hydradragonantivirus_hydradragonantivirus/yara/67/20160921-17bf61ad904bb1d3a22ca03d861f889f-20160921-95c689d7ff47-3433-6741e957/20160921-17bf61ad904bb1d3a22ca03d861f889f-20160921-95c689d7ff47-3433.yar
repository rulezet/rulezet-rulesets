rule _20160921_17bf61ad904bb1d3a22ca03d861f889f_20160921_95c689d7ff47_3433 {
  meta:
    description = "datamaliciousorder - from files 20160921_17bf61ad904bb1d3a22ca03d861f889f.js, 20160921_95c689d7ff4700a03d604b71aaf3634b.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "3ad9770f05718e622431ef5405e0a702ec2484ecc5b434b1a634c99b480bc855"
    hash2       = "5783f1dc6f93c438a9ac56abe49d6a41942b0b140e5fe608a7748f646ea646e7"

  strings:
    $s1 = "n fuck(){return \"Nm\";})(),(function fuck(){return \"Xw\";})(),(function fuck(){return \"IPu\";})(),(function fuck(){return \"D" ascii
    $s2 = "ion fuck(){return \"IRn\";})(),(function fuck(){return \"MBg\";})(),(function fuck(){return \"LGo\";})(),(function fuck(){return" ascii
    $s3 = "})(),(function fuck(){return \"Et\";})(),(function fuck(){return \"Et\";})(),(function fuck(){return \"IRn\";})(),(function fuck" ascii
    $s4 = "nction fuck(){return \"Et\";})(),(function fuck(){return \"Et\";})(),(function fuck(){return \"Et\";})(),(function fuck(){return" ascii
    $s5 = "})(),(function fuck(){return \"Et\";})(),(function fuck(){return \"Et\";})(),(function fuck(){return \"Et\";})(),(function fuck(" ascii
    $s6 = " fuck(){return \"Et\";})(),(function fuck(){return \"ADy\";})(),(function fuck(){return \"NKq\";})(),(function fuck(){return \"G" ascii

  condition:
    (uint16(0) == 0x2f0a and (all of them)
    ) or (all of them)
}