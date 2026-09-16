rule _20160921_5e78b76ea160d891abcb41db9983d51f_20160921_a2f8f3f44ef6_3825 {
  meta:
    description = "datamaliciousorder - from files 20160921_5e78b76ea160d891abcb41db9983d51f.js, 20160921_a2f8f3f44ef6a3341feac8fb57e829ce.js, 20160921_abc9044816c2455dc24ac338746b6bd5.js, 20160921_eda7773555acd8e0be7f4e8bf6d0b010.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "789149d5f226f5eb3642909acb465b5f94d946ee53a79d693b40f83359c4471f"
    hash2       = "619e82812300e58dd7cd06b8fbcf2f7e3f6757812cc075603c82363ab6481758"
    hash3       = "2bb53920235afb1c2d16f013bc118d1df64065eefc10c1b2b9e7a4b133850850"
    hash4       = "af4e0a7c109ffa140c9db57a44bcd9c5d9b5a7c75daded0b422d2cec24c01c8b"

  strings:
    $s1 = "return \"IRn\";})(),(function fuck(){return \"MBg\";})(),(function fuck(){return \"IKv\";})(),(function fuck(){return \"UOe\";})" ascii
    $s2 = " fuck(){return \"USf\";})(),(function fuck(){return \"Jo\";})(),(function fuck(){return \"UOe\";})(),(function fuck(){return \"N" ascii
    $s3 = "Vb\";})(),(function fuck(){return \"Vb\";})(),(function fuck(){return \"Np\";})(),(function fuck(){return \"Hs\";})(),(function " ascii
    $s4 = " fuck(){return \"IRn\";})(),(function fuck(){return \"MBg\";})(),(function fuck(){return \"IKv\";})(),(function fuck(){return \"" ascii
    $s5 = "{return \"MBg\";})(),(function fuck(){return \"Vb\";})(),(function fuck(){return \"LGo\";})(),(function fuck(){return \"Hs\";})(" ascii
    $s6 = "k(){return \"IKv\";})(),(function fuck(){return \"Hs\";})(),(function fuck(){return \"RAi\";})(),(function fuck(){return \"USf\"" ascii

  condition:
    (uint16(0) == 0x2f0a and (all of them)
    ) or (all of them)
}