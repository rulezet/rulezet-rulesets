rule _20160921_203e0165d7eb1b32389bd0efd4bc9546_20160921_6db2cb585eb9_3500 {
  meta:
    description = "datamaliciousorder - from files 20160921_203e0165d7eb1b32389bd0efd4bc9546.js, 20160921_6db2cb585eb933d83d07b47d979b00ec.js, 20160921_e26fc4dc1ccef911251bba0675c76ce0.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "b9112c30f4cc79af123a3f3e13b1e01a29f2419955988701cb25a673fdfe684d"
    hash2       = "b98c5953d102d77c680619bcfd3ba762b3a28a14355f65c479544c745a7c9a12"
    hash3       = "f1074dcd9f3ae62af13634c9f88af0a235b2e315a2697fc222ce96bad51ca1a1"

  strings:
    $s1 = "function fuck(){return \"Mw\";})(),(function fuck(){return \"OPz\";})(),(function fuck(){return \"IPu\";})(),(function fuck(){re" ascii
    $s2 = "FJs\";})(),(function fuck(){return \"ADy\";})(),(function fuck(){return \"DRx\";})(),(function fuck(){return \"XHj\";})(),(funct" ascii
    $s3 = "k(){return \"Wo0\";})(),(function fuck(){return \"UOe\";})(),(function fuck(){return \"DRx\";})(),(function fuck(){return \"XHj" ascii
    $s4 = "),(function fuck(){return \"Yk\";})(),(function fuck(){return \"Yk\";})(),(function fuck(){return \"Jg\";})(),(function fuck(){r" ascii
    $s5 = "ck(){return \"ZVi\";})(),(function fuck(){return \"Np\";})(),(function fuck(){return \"IPu\";})(),(function fuck(){return \"DRx" ascii
    $s6 = "\"RAi\";})(),(function fuck(){return \"DRx\";})(),(function fuck(){return \"MIl\";})(),(function fuck(){return \"XCr\";})(),(fun" ascii

  condition:
    (uint16(0) == 0x2f0a and (all of them)
    ) or (all of them)
}