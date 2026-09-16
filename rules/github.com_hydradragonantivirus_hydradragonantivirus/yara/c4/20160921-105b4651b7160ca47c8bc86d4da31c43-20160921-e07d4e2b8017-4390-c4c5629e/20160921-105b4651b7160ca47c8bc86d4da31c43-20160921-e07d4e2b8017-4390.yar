rule _20160921_105b4651b7160ca47c8bc86d4da31c43_20160921_e07d4e2b8017_4390 {
  meta:
    description = "datamaliciousorder - from files 20160921_105b4651b7160ca47c8bc86d4da31c43.js, 20160921_e07d4e2b80172d933515ba35e18c07eb.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "8e64d089e7076541ade19a5701fb8571545dde4a6c002b31df5fef02095005f7"
    hash2       = "d93efcba4ba3ef570f21adda2cc5413ab9ed3865a53a97ad1e05113ebc7c4787"

  strings:
    $s1 = "urn \"IPu\";})(),(function fuck(){return \"OQr\";})(),(function fuck(){return \"LGo\";})(),(function fuck(){return \"Hs\";})(),(" ascii
    $s2 = "ck(){return \"Jo\";})(),(function fuck(){return \"UOe\";})(),(function fuck(){return \"Np\";})(),(function fuck(){return \"IPu\"" ascii
    $s3 = "rn \"Jo\";})(),(function fuck(){return \"UOe\";})(),(function fuck(){return \"MOj\";})(),(function fuck(){return \"NKq\";})(),(f" ascii
    $s4 = "LGo\";})(),(function fuck(){return \"Hs\";})(),(function fuck(){return \"Np\";})(),(function fuck(){return \"MOj\";})(),(functio" ascii
    $s5 = "(){return \"GJx\";})(),(function fuck(){return \"XFd\";})(),(function fuck(){return \"Dc\";})(),(function fuck(){return \"IRn\";" ascii

  condition:
    (uint16(0) == 0x2f0a and (all of them)
    ) or (all of them)
}