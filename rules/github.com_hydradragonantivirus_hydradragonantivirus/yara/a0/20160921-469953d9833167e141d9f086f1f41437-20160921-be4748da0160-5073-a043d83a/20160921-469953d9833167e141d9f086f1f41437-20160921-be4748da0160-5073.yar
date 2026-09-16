rule _20160921_469953d9833167e141d9f086f1f41437_20160921_be4748da0160_5073 {
  meta:
    description = "datamaliciousorder - from files 20160921_469953d9833167e141d9f086f1f41437.js, 20160921_be4748da01602fdf2d9ffd03054028e4.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "e29808d818b8f5ea60d0baa8d6c3284d3673878f7f4309c5981ced86dc40c5f1"
    hash2       = "4847889a558b3e0b60d671ec5082e36330f771c8789f9ae89683bf49e7128616"

  strings:
    $s1 = "turn \"CCb\";})(),(function fuck(){return \"ZVi\";})(),(function fuck(){return \"Np\";})(),(function fuck(){return \"TTs\";})()," ascii
    $s2 = "nction fuck(){return \"DRx\";})(),(function fuck(){return \"IPu\";})(),(function fuck(){return \"Et\";})(),(function fuck(){retu" ascii
    $s3 = "{return \"Yk\";})(),(function fuck(){return \"Ik\";})(),(function fuck(){return \"IRn\";})(),(function fuck(){return \"OQr\";})(" ascii
    $s4 = "k(){return \"TTs\";})(),(function fuck(){return \"Wo\";})(),(function fuck(){return \"Jh\";})(),(function fuck(){return \"IPu\";" ascii
    $s5 = "(){return \"Yb\";})(),(function fuck(){return \"IPu\";})(),(function fuck(){return \"Et\";})(),(function fuck(){return \"ZWu\";}" ascii

  condition:
    (uint16(0) == 0x2f0a and (all of them)
    ) or (all of them)
}