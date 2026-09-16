rule _20160921_38e907d029606ca83f20849ef282e9ea_20160921_7849aa9596f1_4946 {
  meta:
    description = "datamaliciousorder - from files 20160921_38e907d029606ca83f20849ef282e9ea.js, 20160921_7849aa9596f1b90468a6e3049d3c7482.js, 20160921_a82451728dd7bfad408a4db2acb0fdc4.js, 20160921_c330005443bf481e5f5fac8acbb85145.js, 20160921_db727bb0ba7a4addd64ea2ef7f7475f0.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "5a7c94fb58ddb4d2f337bf953d69adaa2c112a46daf304e06dcfb7cf8ebb0b9d"
    hash2       = "3d31ab296868269e376de237639f2fc64156cbd269cfe7201c3752a4e9fa11df"
    hash3       = "cc029dbbbae3e50c3897c9dba3b4e8d6d1ac7ce9c394a88923879538b37740cd"
    hash4       = "48b88395d1349b5b2e0a815e59769a737e11cc9a098f2346b628ab4ae088b44a"
    hash5       = "12f83f9c7412fb362b5d1e9209d11bdf03d66f9505ff4d2247b8a85f687d4cb8"

  strings:
    $s1 = "})(),(function fuck(){return \"Ai\";})(),(function fuck(){return \"Jg\";})(),(function fuck(){return \"IPu\";})(),(function fuck" ascii
    $s2 = "\";})(),(function fuck(){return \"LGo\";})(),(function fuck(){return \"GNm\";})(),(function fuck(){return \"AUx\";})(),(function" ascii
    $s3 = "fuck(){return \"IPu\";})(),(function fuck(){return \"Ai\";})(),(function fuck(){return \"XFd\";})(),(function fuck(){return \"DA" ascii
    $s4 = "uck(){return \"MBg\";})(),(function fuck(){return \"AUx\";})(),(function fuck(){return \"RAi\";})(),(function fuck(){return \"Np" ascii
    $s5 = "ck(){return \"Wo0\";})(),(function fuck(){return \"Ot\";})(),(function fuck(){return \"Py\";})(),(function fuck(){return \"GNm\"" ascii

  condition:
    (uint16(0) == 0x2f0a and (all of them)
    ) or (all of them)
}