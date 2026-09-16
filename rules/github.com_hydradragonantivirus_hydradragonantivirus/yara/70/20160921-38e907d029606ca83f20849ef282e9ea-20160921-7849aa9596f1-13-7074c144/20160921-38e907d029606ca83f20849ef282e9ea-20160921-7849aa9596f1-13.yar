rule _20160921_38e907d029606ca83f20849ef282e9ea_20160921_7849aa9596f1_13 {
  meta:
    description = "datamaliciousorder - from files 20160921_38e907d029606ca83f20849ef282e9ea.js, 20160921_7849aa9596f1b90468a6e3049d3c7482.js, 20160921_a82451728dd7bfad408a4db2acb0fdc4.js, 20160921_c330005443bf481e5f5fac8acbb85145.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "5a7c94fb58ddb4d2f337bf953d69adaa2c112a46daf304e06dcfb7cf8ebb0b9d"
    hash2       = "3d31ab296868269e376de237639f2fc64156cbd269cfe7201c3752a4e9fa11df"
    hash3       = "cc029dbbbae3e50c3897c9dba3b4e8d6d1ac7ce9c394a88923879538b37740cd"
    hash4       = "48b88395d1349b5b2e0a815e59769a737e11cc9a098f2346b628ab4ae088b44a"

  strings:
    $s1  = "x\";})(),(function fuck(){return \"IPu\";})(),(function fuck(){return \"YQt\";})(),(function fuck(){return \"IRn\";})(),(functio" ascii
    $s2  = "ion fuck(){return \"YQt\";})(),(function fuck(){return \"USf\";})(),(function fuck(){return \"NKq\";})(),(function fuck(){return" ascii
    $s3  = "nction fuck(){return \"IOs\";})(),(function fuck(){return \"AUx\";})(),(function fuck(){return \"IPu\";})(),(function fuck(){ret" ascii
    $s4  = "k(){return \"IPu\";})(),(function fuck(){return \"Ot\";})(),(function fuck(){return \"Ik\";})(),(function fuck(){return \"Np\";}" ascii
    $s5  = "(){return \"LGo\";})(),(function fuck(){return \"YQt\";})(),(function fuck(){return \"ADy\";})(),(function fuck(){return \"IPu\"" ascii
    $s6  = "uck(){return \"DRx\";})(),(function fuck(){return \"IPu\";})(),(function fuck(){return \"LGo\";})(),(function fuck(){return \"YQ" ascii
    $s7  = "{return \"Za\";})(),(function fuck(){return \"IPu\";})(),(function fuck(){return \"Hs\";})(),(function fuck(){return \"Wo\";})()" ascii
    $s8  = ")(),(function fuck(){return \"IPu\";})(),(function fuck(){return \"Hs\";})(),(function fuck(){return \"Fv\";})(),(function fuck(" ascii
    $s9  = "a\";})(),(function fuck(){return \"IPu\";})(),(function fuck(){return \"ZLd\";})(),(function fuck(){return \"Wo0\";})(),(functio" ascii
    $s10 = "uck(){return \"IPu\";})(),(function fuck(){return \"MIl\";})(),(function fuck(){return \"QTc\";})(),(function fuck(){return \"YQ" ascii
    $s11 = "(){return \"We\";})(),(function fuck(){return \"IOs\";})(),(function fuck(){return \"UOe\";})(),(function fuck(){return \"DRx\";" ascii
    $s12 = ")(),(function fuck(){return \"RAi\";})(),(function fuck(){return \"AUx\";})(),(function fuck(){return \"Vb\";})(),(function fuck" ascii
    $s13 = "eturn \"Za\";})(),(function fuck(){return \"IPu\";})(),(function fuck(){return \"Ai\";})(),(function fuck(){return \"Qh\";})(),(" ascii
    $s14 = "turn \"IPu\";})(),(function fuck(){return \"OQr\";})(),(function fuck(){return \"PDf\";})(),(function fuck(){return \"Et\";})()," ascii
    $s15 = "ion fuck(){return \"IPu\";})(),(function fuck(){return \"Wo0\";})(),(function fuck(){return \"Av\";})(),(function fuck(){return " ascii
    $s16 = "ion fuck(){return \"DRx\";})(),(function fuck(){return \"IPu\";})(),(function fuck(){return \"Jo\";})(),(function fuck(){return " ascii
    $s17 = "tion fuck(){return \"AUx\";})(),(function fuck(){return \"RAi\";})(),(function fuck(){return \"RAi\";})(),(function fuck(){retur" ascii
    $s18 = "(),(function fuck(){return \"XHj\";})(),(function fuck(){return \"KVh\";})(),(function fuck(){return \"GNm\";})(),(function fuck" ascii
    $s19 = "{return \"IKv\";})(),(function fuck(){return \"AUx\";})(),(function fuck(){return \"Vb\";})(),(function fuck(){return \"ADy\";})" ascii
    $s20 = "){return \"Vb\";})(),(function fuck(){return \"LGo\";})(),(function fuck(){return \"YQt\";})(),(function fuck(){return \"IPu\";}" ascii

  condition:
    (uint16(0) == 0x2f0a and (8 of them)
    ) or (all of them)
}