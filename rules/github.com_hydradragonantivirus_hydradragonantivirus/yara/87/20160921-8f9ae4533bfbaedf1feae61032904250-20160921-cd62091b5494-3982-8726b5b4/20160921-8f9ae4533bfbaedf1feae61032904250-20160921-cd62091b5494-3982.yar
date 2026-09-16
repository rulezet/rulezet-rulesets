rule _20160921_8f9ae4533bfbaedf1feae61032904250_20160921_cd62091b5494_3982 {
  meta:
    description = "datamaliciousorder - from files 20160921_8f9ae4533bfbaedf1feae61032904250.js, 20160921_cd62091b54940830ea3695d380fd97d8.js, 20160921_e01bb59eb24d1686f9e2aeb1c9237853.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "f093836b93b9b87ed10341ee30bc818ac497c91c6d0dd2b00ab5d3b1822868f9"
    hash2       = "e00553588533d1015b71812c5877864382cbfd2a3a204b4cab76c38ee65ce58c"
    hash3       = "6f5c056ecbe8fe7bc86b4862d32e261ec2bc26cff4b18206988fdb1c7059557c"

  strings:
    $s1 = ";})(),(function fuck(){return \"DRx\";})(),(function fuck(){return \"Zy\";})(),(function fuck(){return \"Jo\";})(),(function fuc" ascii
    $s2 = "){return \"TTs\";})(),(function fuck(){return \"Wo0\";})(),(function fuck(){return \"ZVi\";})(),(function fuck(){return \"IRn\";" ascii
    $s3 = "nction fuck(){return \"Py\";})(),(function fuck(){return \"DRx\";})(),(function fuck(){return \"Zy\";})(),(function fuck(){retur" ascii
    $s4 = "n \"Et\";})(),(function fuck(){return \"MIl\";})(),(function fuck(){return \"Py\";})(),(function fuck(){return \"MOj\";})(),(fun" ascii
    $s5 = " fuck(){return \"IPu\";})(),(function fuck(){return \"Hs\";})(),(function fuck(){return \"ZLd\";})(),(function fuck(){return \"J" ascii
    $s6 = "(){return \"Jh\";})(),(function fuck(){return \"UOe\";})(),(function fuck(){return \"DRx\";})(),(function fuck(){return \"Wo0\";" ascii

  condition:
    (uint16(0) == 0x2f0a and (all of them)
    ) or (all of them)
}