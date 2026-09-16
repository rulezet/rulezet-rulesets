rule _20160921_0de23a42684ac14027d562ff3e5fb6a8_20160921_35d4c12af7a9_4365 {
  meta:
    description = "datamaliciousorder - from files 20160921_0de23a42684ac14027d562ff3e5fb6a8.js, 20160921_35d4c12af7a9481959a41a055c396673.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "7237be0906b854ec3890943cde0c9a731117b836078be4256fe37413dd372a66"
    hash2       = "1c2412951fad30bb8b34aca279acd07c03a437936261b0d90334331b98cf1e99"

  strings:
    $s1 = "ion fuck(){return \"Qh\";})(),(function fuck(){return \"DWe\";})(),(function fuck(){return \"AUx\";})(),(function fuck(){return " ascii
    $s2 = "(),(function fuck(){return \"UOe\";})(),(function fuck(){return \"Ai\";})(),(function fuck(){return \"IRn\";})(),(function fuck(" ascii
    $s3 = "n \"Yk\";})(),(function fuck(){return \"Py\";})(),(function fuck(){return \"AUx\";})(),(function fuck(){return \"USf\";})(),(fun" ascii
    $s4 = " fuck(){return \"IPu\";})(),(function fuck(){return \"Yk\";})(),(function fuck(){return \"Dc\";})(),(function fuck(){return \"RA" ascii
    $s5 = "turn \"Sx\";})(),(function fuck(){return \"Vb\";})(),(function fuck(){return \"IPu\";})(),(function fuck(){return \"DRx\";})(),(" ascii

  condition:
    (uint16(0) == 0x2f0a and (all of them)
    ) or (all of them)
}