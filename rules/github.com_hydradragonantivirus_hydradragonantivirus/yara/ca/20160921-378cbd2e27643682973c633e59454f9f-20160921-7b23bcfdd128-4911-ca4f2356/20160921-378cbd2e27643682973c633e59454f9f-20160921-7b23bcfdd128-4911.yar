rule _20160921_378cbd2e27643682973c633e59454f9f_20160921_7b23bcfdd128_4911 {
  meta:
    description = "datamaliciousorder - from files 20160921_378cbd2e27643682973c633e59454f9f.js, 20160921_7b23bcfdd1289634cd9a4c73f4cbb144.js, 20160921_9b80c329004df146d978cb7b31b22c05.js, 20160921_e26fc4dc1ccef911251bba0675c76ce0.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "8ce016002e44e1fbf4624122138e5a8b0261aff6487c52da0d644398da46a896"
    hash2       = "7a94fbc46ac51a544406f9a59bf405cd1e19e8e6681d7feacbc81e5ab7d4a50b"
    hash3       = "d0ec644cd7307cbd280d369539e9834d3ad2ba0909b631b5a3640f8f6a1105d1"
    hash4       = "f1074dcd9f3ae62af13634c9f88af0a235b2e315a2697fc222ce96bad51ca1a1"

  strings:
    $s1 = "tion fuck(){return \"Jo\";})(),(function fuck(){return \"Xw\";})(),(function fuck(){return \"MOj\";})(),(function fuck(){return " ascii
    $s2 = "Bg\";})(),(function fuck(){return \"MBg\";})(),(function fuck(){return \"IPu\";})(),(function fuck(){return \"Xw\";})(),(functio" ascii
    $s3 = ";})(),(function fuck(){return \"Fv\";})(),(function fuck(){return \"Mw\";})(),(function fuck(){return \"Yk\";})(),(function fuck" ascii
    $s4 = "ck(){return \"GJx\";})(),(function fuck(){return \"Ik\";})(),(function fuck(){return \"Ar\";})(),(function fuck(){return \"Xg\";" ascii
    $s5 = "){return \"Ik\";})(),(function fuck(){return \"Sx\";})(),(function fuck(){return \"KVh\";})(),(function fuck(){return \"UOe\";})" ascii

  condition:
    (uint16(0) == 0x2f0a and (all of them)
    ) or (all of them)
}