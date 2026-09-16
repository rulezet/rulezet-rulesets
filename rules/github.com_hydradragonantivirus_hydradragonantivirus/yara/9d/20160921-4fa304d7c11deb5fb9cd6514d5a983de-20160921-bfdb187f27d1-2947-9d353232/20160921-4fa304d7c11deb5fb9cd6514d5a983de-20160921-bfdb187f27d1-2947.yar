rule _20160921_4fa304d7c11deb5fb9cd6514d5a983de_20160921_bfdb187f27d1_2947 {
  meta:
    description = "datamaliciousorder - from files 20160921_4fa304d7c11deb5fb9cd6514d5a983de.js, 20160921_bfdb187f27d136f64e05f0dcf2ee4914.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "cef5a1e67f57d9f24065ff0145644e0185df6abc29113310c6782b30e0a9236b"
    hash2       = "cbf2173e7b067de6ce6bf189ba38c78f3f0d97a7e6685c0191e08885badfeb3e"

  strings:
    $s1 = "turn \"Cd\";})(),(function fuck(){return \"Py\";})(),(function fuck(){return \"MUs\";})(),(function fuck(){return \"IPu\";})(),(" ascii
    $s2 = "n \"CTm\";})(),(function fuck(){return \"Cd\";})(),(function fuck(){return \"Py\";})(),(function fuck(){return \"MUs\";})(),(fun" ascii
    $s3 = " fuck(){return \"DRx\";})(),(function fuck(){return \"IPu\";})(),(function fuck(){return \"Py\";})(),(function fuck(){return \"Z" ascii
    $s4 = ",(function fuck(){return \"TTs\";})(),(function fuck(){return \"Py\";})(),(function fuck(){return \"To\";})(),(function fuck(){r" ascii
    $s5 = "k(){return \"Nm\";})(),(function fuck(){return \"DWe\";})(),(function fuck(){return \"Fv\";})(),(function fuck(){return \"IRn\";" ascii
    $s6 = "ion fuck(){return \"CTm\";})(),(function fuck(){return \"CTm\";})(),(function fuck(){return \"Cd\";})(),(function fuck(){return " ascii
    $s7 = ",(function fuck(){return \"Ug\";})(),(function fuck(){return \"Na\";})(),(function fuck(){return \"IPu\";})(),(function fuck(){r" ascii

  condition:
    (uint16(0) == 0x2f0a and (all of them)
    ) or (all of them)
}