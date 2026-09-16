rule _20160921_19fa56ffee6d867aeed604f46a4d4fe9_20160921_21ea22d345e7_4571 {
  meta:
    description = "datamaliciousorder - from files 20160921_19fa56ffee6d867aeed604f46a4d4fe9.js, 20160921_21ea22d345e757ea2f8e6336a9555502.js, 20160921_eb528bac8085eeec9ca6760c41b0a818.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "988e83dedf7c32629210ef0407bb0e576898ac66d605c942d70e189051f472fd"
    hash2       = "e8743d09e1e870afab5e1ecd8d21f82873a9da6a025b74f14bc65477cea8f023"
    hash3       = "cde7bce07f038dbcc12ab3207be0245adc184f6540d425dd1ec837861c3e4440"

  strings:
    $s1 = " \"Mw\";})(),(function fuck(){return \"Jo\";})(),(function fuck(){return \"Mw\";})(),(function fuck(){return \"DWe\";})(),(funct" ascii
    $s2 = "u\";})(),(function fuck(){return \"LGo\";})(),(function fuck(){return \"YQt\";})(),(function fuck(){return \"NKq\";})(),(functio" ascii
    $s3 = " fuck(){return \"KVh\";})(),(function fuck(){return \"UOe\";})(),(function fuck(){return \"YQt\";})(),(function fuck(){return \"" ascii
    $s4 = "eturn \"DAa\";})(),(function fuck(){return \"Ar\";})(),(function fuck(){return \"OQr\";})(),(function fuck(){return \"Nm\";})()," ascii
    $s5 = "nction fuck(){return \"IRn\";})(),(function fuck(){return \"MBg\";})(),(function fuck(){return \"AUx\";})(),(function fuck(){ret" ascii

  condition:
    (uint16(0) == 0x2f0a and (all of them)
    ) or (all of them)
}