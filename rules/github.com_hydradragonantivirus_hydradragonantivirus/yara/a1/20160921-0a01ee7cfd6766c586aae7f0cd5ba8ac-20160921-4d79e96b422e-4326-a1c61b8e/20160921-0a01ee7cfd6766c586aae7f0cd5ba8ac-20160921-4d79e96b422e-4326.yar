rule _20160921_0a01ee7cfd6766c586aae7f0cd5ba8ac_20160921_4d79e96b422e_4326 {
  meta:
    description = "datamaliciousorder - from files 20160921_0a01ee7cfd6766c586aae7f0cd5ba8ac.js, 20160921_4d79e96b422e6679059a17d9524e032c.js, 20160921_a84d89efd5400c906c1132a56b0ef679.js, 20160921_fa18251c4ecf88527d80b62724da7b36.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "ab92df4d278f844bff1f6b011a9c332faae5828bb4324384139b2829693be23b"
    hash2       = "d5794a16a28dba8e89768fa9195da33a7e28c3da5fc73a7789e7c04395f23f06"
    hash3       = "f3cfecdabdf17d9af410d0fee7ec88844bc361668aca1a114832bd3e515d3456"
    hash4       = "21b811f7ccb44c8d67ee516b8cfe4393b6e248d9db38cab4200e9794e3da737f"

  strings:
    $s1 = "(){return \"ZWu\";})(),(function fuck(){return \"ZLd\";})(),(function fuck(){return \"YAv\";})(),(function fuck(){return \"IPu\"" ascii
    $s2 = "unction fuck(){return \"QTc\";})(),(function fuck(){return \"DRx\";})(),(function fuck(){return \"XCr\";})(),(function fuck(){re" ascii
    $s3 = "ck(){return \"Sx\";})(),(function fuck(){return \"GNm\";})(),(function fuck(){return \"DRx\";})(),(function fuck(){return \"We\"" ascii
    $s4 = ",(function fuck(){return \"IRn\";})(),(function fuck(){return \"OQr\";})(),(function fuck(){return \"Hs\";})(),(function fuck(){" ascii
    $s5 = " \"Wo0\";})(),(function fuck(){return \"ZVi\";})(),(function fuck(){return \"DRx\";})(),(function fuck(){return \"Zy\";})(),(fun" ascii

  condition:
    (uint16(0) == 0x2f0a and (all of them)
    ) or (all of them)
}