rule _20160921_01da6b0c1b5614c5877e0dd7b6be4036_20160921_17642c69cbfb_4129 {
  meta:
    description = "datamaliciousorder - from files 20160921_01da6b0c1b5614c5877e0dd7b6be4036.js, 20160921_17642c69cbfb276056f3695ae22dad4c.js, 20160921_38e907d029606ca83f20849ef282e9ea.js, 20160921_5831ee10eea30ef3b8363cda03eba31a.js, 20160921_7849aa9596f1b90468a6e3049d3c7482.js, 20160921_a82451728dd7bfad408a4db2acb0fdc4.js, 20160921_c330005443bf481e5f5fac8acbb85145.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "5da941f7d098e0926acf7ad9efedc9f91495115fc83f288580eba79e44574693"
    hash2       = "4cdbf9fba4e3fec424cf182fd21fa3c400b0649ca09f140375a47df12248955c"
    hash3       = "5a7c94fb58ddb4d2f337bf953d69adaa2c112a46daf304e06dcfb7cf8ebb0b9d"
    hash4       = "2249c045e34389dbbb9e3554dc23ae5207cc7f4205df2feaede6b0df279995cb"
    hash5       = "3d31ab296868269e376de237639f2fc64156cbd269cfe7201c3752a4e9fa11df"
    hash6       = "cc029dbbbae3e50c3897c9dba3b4e8d6d1ac7ce9c394a88923879538b37740cd"
    hash7       = "48b88395d1349b5b2e0a815e59769a737e11cc9a098f2346b628ab4ae088b44a"

  strings:
    $s1 = "n \"MBg\";})(),(function fuck(){return \"XFd\";})(),(function fuck(){return \"Sx\";})(),(function fuck(){return \"IPu\";})(),(fu" ascii
    $s2 = "y\";})(),(function fuck(){return \"TTs\";})(),(function fuck(){return \"We\";})(),(function fuck(){return \"Vf\";})(),(function " ascii
    $s3 = "tion fuck(){return \"IPu\";})(),(function fuck(){return \"Vf\";})(),(function fuck(){return \"Jh\";})(),(function fuck(){return " ascii
    $s4 = "return \"GWo\";})(),(function fuck(){return \"LGo\";})(),(function fuck(){return \"IPu\";})(),(function fuck(){return \"DRx\";})" ascii
    $s5 = "})(),(function fuck(){return \"MBg\";})(),(function fuck(){return \"Cd\";})(),(function fuck(){return \"YAv\";})(),(function fuc" ascii

  condition:
    (uint16(0) == 0x2f0a and (all of them)
    ) or (all of them)
}