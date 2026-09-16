rule _20160921_38e907d029606ca83f20849ef282e9ea_20160921_3a2902eaca0b_1841 {
  meta:
    description = "datamaliciousorder - from files 20160921_38e907d029606ca83f20849ef282e9ea.js, 20160921_3a2902eaca0b2b91120958418b46c844.js, 20160921_5cc1e2fc6d6fe845510388bfa2dd1826.js, 20160921_7849aa9596f1b90468a6e3049d3c7482.js, 20160921_a82451728dd7bfad408a4db2acb0fdc4.js, 20160921_c330005443bf481e5f5fac8acbb85145.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "5a7c94fb58ddb4d2f337bf953d69adaa2c112a46daf304e06dcfb7cf8ebb0b9d"
    hash2       = "063bab1922376d926db97bdcd4342c2e9b0f2ec98d9fad81c2a3f86537c82b07"
    hash3       = "8517cbcc9f90e7835f4bbbef31cd3779f0298cca7076dd98e48fb69d359f4820"
    hash4       = "3d31ab296868269e376de237639f2fc64156cbd269cfe7201c3752a4e9fa11df"
    hash5       = "cc029dbbbae3e50c3897c9dba3b4e8d6d1ac7ce9c394a88923879538b37740cd"
    hash6       = "48b88395d1349b5b2e0a815e59769a737e11cc9a098f2346b628ab4ae088b44a"

  strings:
    $s1  = " fuck(){return \"IPu\";})(),(function fuck(){return \"Et\";})(),(function fuck(){return \"IOs\";})(),(function fuck(){return \"I" ascii
    $s2  = "Rx\";})(),(function fuck(){return \"Cd\";})(),(function fuck(){return \"XHj\";})(),(function fuck(){return \"GWo\";})(),(functio" ascii
    $s3  = "rn \"EHo\";})(),(function fuck(){return \"UOe\";})(),(function fuck(){return \"IRn\";})(),(function fuck(){return \"OQr\";})(),(" ascii
    $s4  = "\";})(),(function fuck(){return \"Qh\";})(),(function fuck(){return \"Sx\";})(),(function fuck(){return \"IPu\";})(),(function f" ascii
    $s5  = " fuck(){return \"Oh\";})(),(function fuck(){return \"Vf\";})(),(function fuck(){return \"Dc\";})(),(function fuck(){return \"DRx" ascii
    $s6  = "(function fuck(){return \"Et\";})(),(function fuck(){return \"Ot\";})(),(function fuck(){return \"Na\";})(),(function fuck(){ret" ascii
    $s7  = "eturn \"DRx\";})(),(function fuck(){return \"IPu\";})(),(function fuck(){return \"Nm\";})(),(function fuck(){return \"DAa\";})()" ascii
    $s8  = "){return \"DRx\";})(),(function fuck(){return \"ZWu\";})(),(function fuck(){return \"MIl\";})(),(function fuck(){return \"Jh\";}" ascii
    $s9  = "(),(function fuck(){return \"IPu\";})(),(function fuck(){return \"Jo\";})(),(function fuck(){return \"XCr\";})(),(function fuck(" ascii
    $s10 = "n fuck(){return \"Ai\";})(),(function fuck(){return \"FJs\";})(),(function fuck(){return \"IPu\";})(),(function fuck(){return \"" ascii

  condition:
    (uint16(0) == 0x2f0a and (all of them)
    ) or (all of them)
}