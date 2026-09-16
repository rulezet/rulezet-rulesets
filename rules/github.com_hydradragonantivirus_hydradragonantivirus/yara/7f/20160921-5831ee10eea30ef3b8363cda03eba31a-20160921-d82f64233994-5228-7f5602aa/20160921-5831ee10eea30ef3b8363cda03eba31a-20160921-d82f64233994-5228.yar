rule _20160921_5831ee10eea30ef3b8363cda03eba31a_20160921_d82f64233994_5228 {
  meta:
    description = "datamaliciousorder - from files 20160921_5831ee10eea30ef3b8363cda03eba31a.js, 20160921_d82f642339947ac5ef4d322534d8cd70.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "2249c045e34389dbbb9e3554dc23ae5207cc7f4205df2feaede6b0df279995cb"
    hash2       = "1af101b4afb2b8d290446a4841d803e88cb42849fb95f0cea056677487805eb6"

  strings:
    $s1 = "\";})(),(function fuck(){return \"YQt\";})(),(function fuck(){return \"UOe\";})(),(function fuck(){return \"NKq\";})(),(function" ascii
    $s2 = "Ai\";})(),(function fuck(){return \"YQt\";})(),(function fuck(){return \"IRn\";})(),(function fuck(){return \"MBg\";})(),(functi" ascii
    $s3 = "uck(){return \"YQt\";})(),(function fuck(){return \"Np\";})(),(function fuck(){return \"NKq\";})(),(function fuck(){return \"Ug" ascii
    $s4 = "function fuck(){return \"MBg\";})(),(function fuck(){return \"Et\";})(),(function fuck(){return \"ZWu\";})(),(function fuck(){re" ascii
    $s5 = "){return \"AUx\";})(),(function fuck(){return \"RAi\";})(),(function fuck(){return \"RAi\";})(),(function fuck(){return \"ADy\";" ascii

  condition:
    (uint16(0) == 0x2f0a and (all of them)
    ) or (all of them)
}