rule _20160921_5ed9729c3ab2cb9d37d8a088af1aba59_20160921_b714100d69b9_1493 {
  meta:
    description = "datamaliciousorder - from files 20160921_5ed9729c3ab2cb9d37d8a088af1aba59.js, 20160921_b714100d69b955de920a302ff8bef7db.js, 20160921_b74bfd3dc7404d3d5a6512718aa52504.js, 20160921_fa8c93ef210d8b4c6831cb1425f1dc9b.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "c5908838424a9cae8eb5587cff7048056b427db1deb512dcbe9ca852a402e03d"
    hash2       = "fc43d54db3c24d6f7ce2d47a45ffcd0768d5cfe90e405322e477be98fe4a8170"
    hash3       = "359d333ab8fc51d27349ecaec71f8baf8e8aafae5bfe2d6afd26f4ed76e802db"
    hash4       = "7e7bb1d2ade80c23d5462f8e4a470a3c3245b07b8a709a3c911ff76a8c32da35"

  strings:
    $s1  = "return \"LGo\";})(),(function fuck(){return \"MBg\";})(),(function fuck(){return \"Qh\";})(),(function fuck(){return \"DWe\";})(" ascii
    $s2  = "nction fuck(){return \"Ve\";})(),(function fuck(){return \"UXf\";})(),(function fuck(){return \"LGo\";})(),(function fuck(){retu" ascii
    $s3  = ")(),(function fuck(){return \"CTm\";})(),(function fuck(){return \"Tv\";})(),(function fuck(){return \"Qh\";})(),(function fuck(" ascii
    $s4  = ")(),(function fuck(){return \"DAa\";})(),(function fuck(){return \"TTs\";})(),(function fuck(){return \"YQt\";})(),(function fuc" ascii
    $s5  = "n \"LGo\";})(),(function fuck(){return \"ADy\";})(),(function fuck(){return \"MOj\";})(),(function fuck(){return \"IPu\";})(),(f" ascii
    $s6  = "urn \"IPu\";})(),(function fuck(){return \"Ug\";})(),(function fuck(){return \"Zy\";})(),(function fuck(){return \"Ik\";})(),(fu" ascii
    $s7  = "(){return \"Ar\";})(),(function fuck(){return \"MOj\";})(),(function fuck(){return \"GNm\";})(),(function fuck(){return \"Bz\";}" ascii
    $s8  = ")(),(function fuck(){return \"GJx\";})(),(function fuck(){return \"ZVi\";})(),(function fuck(){return \"Np\";})(),(function fuck" ascii
    $s9  = "tion fuck(){return \"Bz\";})()];" fullword ascii
    $s10 = "uck(){return \"Hs\";})(),(function fuck(){return \"IRn\";})(),(function fuck(){return \"OQr\";})(),(function fuck(){return \"Qh" ascii
    $s11 = "turn \"XFd\";})(),(function fuck(){return \"Wo0\";})(),(function fuck(){return \"Jo\";})(),(function fuck(){return \"IPu\";})()," ascii
    $s12 = "\";})(),(function fuck(){return \"CTm\";})(),(function fuck(){return \"Ve\";})(),(function fuck(){return \"UXf\";})(),(function " ascii
    $s13 = "n fuck(){return \"DRx\";})(),(function fuck(){return \"IPu\";})(),(function fuck(){return \"Ve\";})(),(function fuck(){return \"" ascii

  condition:
    (uint16(0) == 0x2f0a and (8 of them)
    ) or (all of them)
}