rule _20160921_5e78b76ea160d891abcb41db9983d51f_20160921_78345276f684_3824 {
  meta:
    description = "datamaliciousorder - from files 20160921_5e78b76ea160d891abcb41db9983d51f.js, 20160921_78345276f684d53628bbcac810994182.js, 20160921_eda7773555acd8e0be7f4e8bf6d0b010.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "789149d5f226f5eb3642909acb465b5f94d946ee53a79d693b40f83359c4471f"
    hash2       = "17b203684b4f2284de883c81e8fef63ea03c36bd0599ccb85d3175be35d9ac6d"
    hash3       = "af4e0a7c109ffa140c9db57a44bcd9c5d9b5a7c75daded0b422d2cec24c01c8b"

  strings:
    $s1 = "n fuck(){return \"MBg\";})(),(function fuck(){return \"OQr\";})(),(function fuck(){return \"Ai\";})(),(function fuck(){return \"" ascii
    $s2 = "function fuck(){return \"IPu\";})(),(function fuck(){return \"XFd\";})(),(function fuck(){return \"Cd\";})(),(function fuck(){re" ascii
    $s3 = "TTs\";})(),(function fuck(){return \"CCb\";})(),(function fuck(){return \"IOs\";})(),(function fuck(){return \"UOe\";})(),(funct" ascii
    $s4 = "return \"Bz\";})(),(function fuck(){return \"CTm\";})(),(function fuck(){return \"CTm\";})(),(function fuck(){return \"Jh\";})()" ascii
    $s5 = " \"OPz\";})(),(function fuck(){return \"IPu\";})(),(function fuck(){return \"Cd\";})(),(function fuck(){return \"Ve\";})(),(func" ascii
    $s6 = "tion fuck(){return \"Jo\";})(),(function fuck(){return \"USf\";})(),(function fuck(){return \"Np\";})(),(function fuck(){return " ascii

  condition:
    (uint16(0) == 0x2f0a and (all of them)
    ) or (all of them)
}