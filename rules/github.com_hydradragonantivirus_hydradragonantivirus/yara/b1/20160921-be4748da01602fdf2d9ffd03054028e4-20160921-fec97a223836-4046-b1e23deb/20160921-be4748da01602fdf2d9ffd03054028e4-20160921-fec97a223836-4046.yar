rule _20160921_be4748da01602fdf2d9ffd03054028e4_20160921_fec97a223836_4046 {
  meta:
    description = "datamaliciousorder - from files 20160921_be4748da01602fdf2d9ffd03054028e4.js, 20160921_fec97a223836973c5d09ac6d41b2ad43.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "4847889a558b3e0b60d671ec5082e36330f771c8789f9ae89683bf49e7128616"
    hash2       = "d8c26b92e119ca52cb4c0aa43351cde4400c3d6abac819e57a391628e14280cb"

  strings:
    $s1 = ")(),(function fuck(){return \"TTs\";})(),(function fuck(){return \"We\";})(),(function fuck(){return \"Jg\";})(),(function fuck(" ascii
    $s2 = "})(),(function fuck(){return \"GNm\";})(),(function fuck(){return \"AUx\";})(),(function fuck(){return \"NKq\";})(),(function fu" ascii
    $s3 = ";})(),(function fuck(){return \"ADy\";})(),(function fuck(){return \"AUx\";})(),(function fuck(){return \"AUx\";})(),(function f" ascii
    $s4 = ",(function fuck(){return \"Ot\";})(),(function fuck(){return \"Ik\";})(),(function fuck(){return \"Np\";})(),(function fuck(){re" ascii
    $s5 = "(){return \"ZWu\";})(),(function fuck(){return \"Hs\";})(),(function fuck(){return \"Ik\";})(),(function fuck(){return \"UOe\";}" ascii
    $s6 = "n \"Qh\";})(),(function fuck(){return \"To\";})(),(function fuck(){return \"Sx\";})(),(function fuck(){return \"RAi\";})(),(func" ascii

  condition:
    (uint16(0) == 0x2f0a and (all of them)
    ) or (all of them)
}