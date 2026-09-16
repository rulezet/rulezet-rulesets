rule _20160921_63a82ecb2e4eb3b0dd878bbec885c469_20160921_fa89d54bd5a7_5313 {
  meta:
    description = "datamaliciousorder - from files 20160921_63a82ecb2e4eb3b0dd878bbec885c469.js, 20160921_fa89d54bd5a7a27defe09d5a56b5a881.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "0e9de62be8773f33e42da56c84c9c85d07f7c2616909543479f7803e6794a9ef"
    hash2       = "30f2a7c2562ef79254c8129be50246b9c41eb24f000c8cfbd0f4f8c28b49b00f"

  strings:
    $s1 = "n fuck(){return \"RAi\";})(),(function fuck(){return \"TTs\";})(),(function fuck(){return \"LGo\";})(),(function fuck(){return " ascii
    $s2 = "fuck(){return \"IPu\";})(),(function fuck(){return \"ZLd\";})(),(function fuck(){return \"Jg\";})(),(function fuck(){return \"IP" ascii
    $s3 = "rn \"Vb\";})(),(function fuck(){return \"Jo\";})(),(function fuck(){return \"Hs\";})(),(function fuck(){return \"IRn\";})(),(fun" ascii
    $s4 = ")(),(function fuck(){return \"Jo\";})(),(function fuck(){return \"LGo\";})(),(function fuck(){return \"IPu\";})(),(function fuck" ascii
    $s5 = "function fuck(){return \"Jo\";})(),(function fuck(){return \"Np\";})(),(function fuck(){return \"IRn\";})(),(function fuck(){ret" ascii

  condition:
    (uint16(0) == 0x2f0a and (all of them)
    ) or (all of them)
}