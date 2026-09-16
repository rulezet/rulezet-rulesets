rule _20160921_4fa304d7c11deb5fb9cd6514d5a983de_20160921_5230866e44ed_3762 {
  meta:
    description = "datamaliciousorder - from files 20160921_4fa304d7c11deb5fb9cd6514d5a983de.js, 20160921_5230866e44eda4e054d929933fdfdae1.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "cef5a1e67f57d9f24065ff0145644e0185df6abc29113310c6782b30e0a9236b"
    hash2       = "4b11d10d6c2a935fa29f47c13ee54d426aac8d667f3bc2f79681ac7e4d365c76"

  strings:
    $s1 = "return \"CTm\";})(),(function fuck(){return \"Vf\";})(),(function fuck(){return \"We\";})(),(function fuck(){return \"Dc\";})()," ascii
    $s2 = "unction fuck(){return \"PDf\";})(),(function fuck(){return \"DAa\";})(),(function fuck(){return \"IPu\";})(),(function fuck(){re" ascii
    $s3 = ",(function fuck(){return \"Dc\";})(),(function fuck(){return \"UOe\";})(),(function fuck(){return \"IRn\";})(),(function fuck(){" ascii
    $s4 = "m\";})(),(function fuck(){return \"CTm\";})(),(function fuck(){return \"CTm\";})(),(function fuck(){return \"Oh\";})(),(function" ascii
    $s5 = "nction fuck(){return \"YQt\";})(),(function fuck(){return \"Sx\";})(),(function fuck(){return \"IPu\";})(),(function fuck(){retu" ascii
    $s6 = "DRx\";})(),(function fuck(){return \"IPu\";})(),(function fuck(){return \"Nm\";})(),(function fuck(){return \"Wo0\";})(),(functi" ascii

  condition:
    (uint16(0) == 0x2f0a and (all of them)
    ) or (all of them)
}