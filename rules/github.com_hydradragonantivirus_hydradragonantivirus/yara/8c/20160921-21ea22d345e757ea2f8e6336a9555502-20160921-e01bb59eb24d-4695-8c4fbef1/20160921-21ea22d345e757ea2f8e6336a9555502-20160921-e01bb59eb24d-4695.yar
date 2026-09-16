rule _20160921_21ea22d345e757ea2f8e6336a9555502_20160921_e01bb59eb24d_4695 {
  meta:
    description = "datamaliciousorder - from files 20160921_21ea22d345e757ea2f8e6336a9555502.js, 20160921_e01bb59eb24d1686f9e2aeb1c9237853.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "e8743d09e1e870afab5e1ecd8d21f82873a9da6a025b74f14bc65477cea8f023"
    hash2       = "6f5c056ecbe8fe7bc86b4862d32e261ec2bc26cff4b18206988fdb1c7059557c"

  strings:
    $s1 = "{return \"GNm\";})(),(function fuck(){return \"IRn\";})(),(function fuck(){return \"DHd\";})(),(function fuck(){return \"USf\";}" ascii
    $s2 = "u\";})(),(function fuck(){return \"OQr\";})(),(function fuck(){return \"Ar\";})(),(function fuck(){return \"TTs\";})(),(function" ascii
    $s3 = "\"TTs\";})(),(function fuck(){return \"LGo\";})(),(function fuck(){return \"IRn\";})(),(function fuck(){return \"IPu\";})(),(fun" ascii
    $s4 = "(function fuck(){return \"USf\";})(),(function fuck(){return \"LGo\";})(),(function fuck(){return \"USf\";})(),(function fuck(){" ascii
    $s5 = "ion fuck(){return \"USf\";})(),(function fuck(){return \"GNm\";})(),(function fuck(){return \"USf\";})(),(function fuck(){return" ascii

  condition:
    (uint16(0) == 0x2f0a and (all of them)
    ) or (all of them)
}