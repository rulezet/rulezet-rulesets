rule _20160921_783ed6ff0d6e1cf80c95099c29564ec0_20160921_b714100d69b9_5418 {
  meta:
    description = "datamaliciousorder - from files 20160921_783ed6ff0d6e1cf80c95099c29564ec0.js, 20160921_b714100d69b955de920a302ff8bef7db.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "91c59edb0e2a43b5780f865f87a5462b55dab1281045b0a38b38ac155b7d34b6"
    hash2       = "fc43d54db3c24d6f7ce2d47a45ffcd0768d5cfe90e405322e477be98fe4a8170"

  strings:
    $s1 = " fuck(){return \"Jo\";})(),(function fuck(){return \"Hs\";})(),(function fuck(){return \"Np\";})(),(function fuck(){return \"IRn" ascii
    $s2 = "return \"Xg\";})(),(function fuck(){return \"Ik\";})(),(function fuck(){return \"GWo\";})(),(function fuck(){return \"NKq\";})()" ascii
    $s3 = " fuck(){return \"IPu\";})(),(function fuck(){return \"ZWu\";})(),(function fuck(){return \"YAv\";})(),(function fuck(){return \"" ascii
    $s4 = "})(),(function fuck(){return \"Xg\";})(),(function fuck(){return \"Zy\";})(),(function fuck(){return \"XCr\";})(),(function fuck" ascii
    $s5 = "Oe\";})(),(function fuck(){return \"TTs\";})(),(function fuck(){return \"XCr\";})(),(function fuck(){return \"XFd\";})(),(functi" ascii

  condition:
    (uint16(0) == 0x2f0a and (all of them)
    ) or (all of them)
}