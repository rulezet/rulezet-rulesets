rule _20160921_38e907d029606ca83f20849ef282e9ea_20160921_7849aa9596f1_4948 {
  meta:
    description = "datamaliciousorder - from files 20160921_38e907d029606ca83f20849ef282e9ea.js, 20160921_7849aa9596f1b90468a6e3049d3c7482.js, 20160921_962ed1e894cd91f421ad984310ce3140.js, 20160921_a82451728dd7bfad408a4db2acb0fdc4.js, 20160921_c330005443bf481e5f5fac8acbb85145.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "5a7c94fb58ddb4d2f337bf953d69adaa2c112a46daf304e06dcfb7cf8ebb0b9d"
    hash2       = "3d31ab296868269e376de237639f2fc64156cbd269cfe7201c3752a4e9fa11df"
    hash3       = "5ddab3f025feef0c562b4f7f707a08e5d6502c7b7178d3d6367d05bae0018033"
    hash4       = "cc029dbbbae3e50c3897c9dba3b4e8d6d1ac7ce9c394a88923879538b37740cd"
    hash5       = "48b88395d1349b5b2e0a815e59769a737e11cc9a098f2346b628ab4ae088b44a"

  strings:
    $s1 = "e\";})(),(function fuck(){return \"Na\";})(),(function fuck(){return \"USf\";})(),(function fuck(){return \"NKq\";})(),(function" ascii
    $s2 = "on fuck(){return \"Xg\";})(),(function fuck(){return \"GNm\";})(),(function fuck(){return \"IRn\";})(),(function fuck(){return " ascii
    $s3 = "on fuck(){return \"Jo\";})(),(function fuck(){return \"SUi\";})(),(function fuck(){return \"YQt\";})(),(function fuck(){return " ascii
    $s4 = "eturn \"CCb\";})(),(function fuck(){return \"ZVi\";})(),(function fuck(){return \"Np\";})(),(function fuck(){return \"TTs\";})()" ascii
    $s5 = "ck(){return \"Ot\";})(),(function fuck(){return \"Py\";})(),(function fuck(){return \"GNm\";})(),(function fuck(){return \"MBg\"" ascii

  condition:
    (uint16(0) == 0x2f0a and (all of them)
    ) or (all of them)
}