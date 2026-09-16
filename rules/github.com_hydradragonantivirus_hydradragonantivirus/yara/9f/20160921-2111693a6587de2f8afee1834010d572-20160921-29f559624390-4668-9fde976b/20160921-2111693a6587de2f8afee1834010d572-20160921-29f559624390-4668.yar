rule _20160921_2111693a6587de2f8afee1834010d572_20160921_29f559624390_4668 {
  meta:
    description = "datamaliciousorder - from files 20160921_2111693a6587de2f8afee1834010d572.js, 20160921_29f559624390fcbd3c9f89ef4a0d5e1d.js, 20160921_b6523fd99592b93c7a07e8a0e3a5eaf2.js, 20160921_c38068bdcf6149dc68d38cbcccfe991f.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "afb04df96413e21fd33fbf65fafdf5fc01cc299acc2cbe099811e60500fbc6d7"
    hash2       = "c15ee6fcf772accd2bb85369b8381c6c2cefb7139e589532becec07720a57867"
    hash3       = "c7380d8ae5ab67e50f821f2074c7903d887706b91f0b0d3dcfedf5bfbd9a62e0"
    hash4       = "d59dd40562ac50a453dbb7054114c62cfd7c63d24b81c776b35af40fb9aa3480"

  strings:
    $s1 = "turn \"Fv\";})(),(function fuck(){return \"Zy\";})(),(function fuck(){return \"Ik\";})(),(function fuck(){return \"Fv\";})(),(fu" ascii
    $s2 = "tion fuck(){return \"We\";})(),(function fuck(){return \"Xg\";})(),(function fuck(){return \"Fv\";})(),(function fuck(){return " ascii
    $s3 = "uck(){return \"QTc\";})(),(function fuck(){return \"NKq\";})(),(function fuck(){return \"Ug\";})(),(function fuck(){return \"Bz" ascii
    $s4 = "function fuck(){return \"Za\";})(),(function fuck(){return \"IPu\";})(),(function fuck(){return \"Yk\";})(),(function fuck(){ret" ascii
    $s5 = "ction fuck(){return \"Yk\";})(),(function fuck(){return \"MUs\";})(),(function fuck(){return \"Pc\";})(),(function fuck(){return" ascii

  condition:
    (uint16(0) == 0x2f0a and (all of them)
    ) or (all of them)
}