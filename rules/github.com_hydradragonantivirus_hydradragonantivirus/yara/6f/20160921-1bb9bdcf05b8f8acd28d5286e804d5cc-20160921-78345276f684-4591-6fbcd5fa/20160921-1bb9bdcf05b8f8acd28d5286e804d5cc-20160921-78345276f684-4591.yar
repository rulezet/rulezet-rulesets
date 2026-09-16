rule _20160921_1bb9bdcf05b8f8acd28d5286e804d5cc_20160921_78345276f684_4591 {
  meta:
    description = "datamaliciousorder - from files 20160921_1bb9bdcf05b8f8acd28d5286e804d5cc.js, 20160921_78345276f684d53628bbcac810994182.js, 20160921_d97203a3a0e9b5b38b8653b55adf994e.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "3937dec3a8d946e214facedccfe7f35e65dbd446a77d077a09996638d7524444"
    hash2       = "17b203684b4f2284de883c81e8fef63ea03c36bd0599ccb85d3175be35d9ac6d"
    hash3       = "4500fdca6df5cc18d7f5e360c950817a72f82196c8ae55d8bcdf74d96a8bba21"

  strings:
    $s1 = " \"MBg\";})(),(function fuck(){return \"LGo\";})(),(function fuck(){return \"RAi\";})(),(function fuck(){return \"Vb\";})(),(fun" ascii
    $s2 = "Vb\";})(),(function fuck(){return \"RAi\";})(),(function fuck(){return \"Vb\";})(),(function fuck(){return \"IRn\";})(),(functio" ascii
    $s3 = "on fuck(){return \"MBg\";})(),(function fuck(){return \"LGo\";})(),(function fuck(){return \"RAi\";})(),(function fuck(){return " ascii
    $s4 = "n fuck(){return \"Vb\";})(),(function fuck(){return \"RAi\";})(),(function fuck(){return \"USf\";})(),(function fuck(){return \"" ascii
    $s5 = "eturn \"Vb\";})(),(function fuck(){return \"RAi\";})(),(function fuck(){return \"LGo\";})(),(function fuck(){return \"IRn\";})()" ascii

  condition:
    (uint16(0) == 0x2f0a and (all of them)
    ) or (all of them)
}