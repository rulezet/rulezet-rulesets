rule _20160921_85f2776f4fe640d2373f51ddbc697659_20160921_d97203a3a0e9_5469 {
  meta:
    description = "datamaliciousorder - from files 20160921_85f2776f4fe640d2373f51ddbc697659.js, 20160921_d97203a3a0e9b5b38b8653b55adf994e.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "0604503e68d6aa73ca3bbdb29b958ea47ad4c81b2f77ad9db2b0e8467b1c870d"
    hash2       = "4500fdca6df5cc18d7f5e360c950817a72f82196c8ae55d8bcdf74d96a8bba21"

  strings:
    $s1 = "(function fuck(){return \"Ai\";})(),(function fuck(){return \"Za\";})(),(function fuck(){return \"Za\";})(),(function fuck(){ret" ascii
    $s2 = "})(),(function fuck(){return \"Ot\";})(),(function fuck(){return \"Qh\";})(),(function fuck(){return \"Dc\";})(),(function fuck(" ascii
    $s3 = "function fuck(){return \"IPu\";})(),(function fuck(){return \"Wo\";})(),(function fuck(){return \"To\";})(),(function fuck(){ret" ascii
    $s4 = "n \"RAi\";})(),(function fuck(){return \"TTs\";})(),(function fuck(){return \"LGo\";})(),(function fuck(){return \"Py\";})(),(fu" ascii
    $s5 = "nction fuck(){return \"Hs\";})(),(function fuck(){return \"RAi\";})(),(function fuck(){return \"UOe\";})(),(function fuck(){retu" ascii

  condition:
    (uint16(0) == 0x2f0a and (all of them)
    ) or (all of them)
}