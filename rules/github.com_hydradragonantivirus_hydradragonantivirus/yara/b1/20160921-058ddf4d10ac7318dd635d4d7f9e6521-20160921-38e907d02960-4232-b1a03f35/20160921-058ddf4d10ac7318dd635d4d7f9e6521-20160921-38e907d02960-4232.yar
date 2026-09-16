rule _20160921_058ddf4d10ac7318dd635d4d7f9e6521_20160921_38e907d02960_4232 {
  meta:
    description = "datamaliciousorder - from files 20160921_058ddf4d10ac7318dd635d4d7f9e6521.js, 20160921_38e907d029606ca83f20849ef282e9ea.js, 20160921_468b13a80ecc75cd21428202c521ca1d.js, 20160921_7849aa9596f1b90468a6e3049d3c7482.js, 20160921_8881f4de1f94ec992ad3832b292063a8.js, 20160921_a82451728dd7bfad408a4db2acb0fdc4.js, 20160921_c330005443bf481e5f5fac8acbb85145.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "beed60d53c1dc194e146ec112b43046bd7ea366584d59483d351cd57e1208385"
    hash2       = "5a7c94fb58ddb4d2f337bf953d69adaa2c112a46daf304e06dcfb7cf8ebb0b9d"
    hash3       = "d9bb117286f85c2017d3323a8a9f5fd0957993945e9e05ef190746247fc90de3"
    hash4       = "3d31ab296868269e376de237639f2fc64156cbd269cfe7201c3752a4e9fa11df"
    hash5       = "708c7205c47d660aa1d234233e251c8ac7e8deb0f5606bd3240bfd2a1f736633"
    hash6       = "cc029dbbbae3e50c3897c9dba3b4e8d6d1ac7ce9c394a88923879538b37740cd"
    hash7       = "48b88395d1349b5b2e0a815e59769a737e11cc9a098f2346b628ab4ae088b44a"

  strings:
    $s1 = "uck(){return \"IKv\";})(),(function fuck(){return \"LGo\";})(),(function fuck(){return \"RAi\";})(),(function fuck(){return \"GN" ascii
    $s2 = " fuck(){return \"USf\";})(),(function fuck(){return \"GNm\";})(),(function fuck(){return \"LGo\";})(),(function fuck(){return \"" ascii
    $s3 = "n fuck(){return \"Sx\";})(),(function fuck(){return \"OQr\";})(),(function fuck(){return \"Za\";})(),(function fuck(){return \"I" ascii
    $s4 = ";})(),(function fuck(){return \"UXf\";})(),(function fuck(){return \"IPu\";})(),(function fuck(){return \"Za\";})(),(function fu" ascii
    $s5 = " \"OPz\";})(),(function fuck(){return \"IPu\";})(),(function fuck(){return \"Ar\";})(),(function fuck(){return \"MOj\";})(),(fun" ascii

  condition:
    (uint16(0) == 0x2f0a and (all of them)
    ) or (all of them)
}