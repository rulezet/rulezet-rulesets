rule _20160921_5ed9729c3ab2cb9d37d8a088af1aba59_20160921_b74bfd3dc740_108 {
  meta:
    description = "datamaliciousorder - from files 20160921_5ed9729c3ab2cb9d37d8a088af1aba59.js, 20160921_b74bfd3dc7404d3d5a6512718aa52504.js, 20160921_fa8c93ef210d8b4c6831cb1425f1dc9b.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "c5908838424a9cae8eb5587cff7048056b427db1deb512dcbe9ca852a402e03d"
    hash2       = "359d333ab8fc51d27349ecaec71f8baf8e8aafae5bfe2d6afd26f4ed76e802db"
    hash3       = "7e7bb1d2ade80c23d5462f8e4a470a3c3245b07b8a709a3c911ff76a8c32da35"

  strings:
    $s1  = "eturn \"ADy\";})(),(function fuck(){return \"Ai\";})(),(function fuck(){return \"Jo\";})(),(function fuck(){return \"LGo\";})()," ascii
    $s2  = "Xg\";})(),(function fuck(){return \"TTs\";})(),(function fuck(){return \"Ai\";})(),(function fuck(){return \"IRn\";})(),(functio" ascii
    $s3  = "n \"IPu\";})(),(function fuck(){return \"Cd\";})(),(function fuck(){return \"MIl\";})(),(function fuck(){return \"Za\";})(),(fun" ascii
    $s4  = " \"Vb\";})(),(function fuck(){return \"UOe\";})(),(function fuck(){return \"Ai\";})(),(function fuck(){return \"NKq\";})(),(func" ascii
    $s5  = "turn \"IPu\";})(),(function fuck(){return \"Vb\";})(),(function fuck(){return \"Ai\";})(),(function fuck(){return \"LGo\";})(),(" ascii
    $s6  = "nction fuck(){return \"RAi\";})(),(function fuck(){return \"Ai\";})(),(function fuck(){return \"Hs\";})(),(function fuck(){retur" ascii
    $s7  = "fuck(){return \"Za\";})(),(function fuck(){return \"UXf\";})(),(function fuck(){return \"IPu\";})(),(function fuck(){return \"Py" ascii
    $s8  = "ion fuck(){return \"Ai\";})(),(function fuck(){return \"Vb\";})(),(function fuck(){return \"IPu\";})(),(function fuck(){return " ascii
    $s9  = "return \"Xw\";})(),(function fuck(){return \"MOj\";})(),(function fuck(){return \"GNm\";})(),(function fuck(){return \"Bz\";})()" ascii
    $s10 = " fuck(){return \"RAi\";})(),(function fuck(){return \"ADy\";})(),(function fuck(){return \"Ai\";})(),(function fuck(){return \"N" ascii
    $s11 = "urn \"USf\";})(),(function fuck(){return \"RAi\";})(),(function fuck(){return \"Ai\";})(),(function fuck(){return \"IRn\";})(),(" ascii
    $s12 = "i\";})(),(function fuck(){return \"Ai\";})(),(function fuck(){return \"Ai\";})(),(function fuck(){return \"Ai\";})(),(function f" ascii
    $s13 = "ck(){return \"LGo\";})(),(function fuck(){return \"USf\";})(),(function fuck(){return \"Jo\";})(),(function fuck(){return \"IPu" ascii
    $s14 = " fuck(){return \"MBg\";})(),(function fuck(){return \"IKv\";})(),(function fuck(){return \"Hs\";})(),(function fuck(){return \"A" ascii
    $s15 = "{return \"RAi\";})(),(function fuck(){return \"Vb\";})(),(function fuck(){return \"Ai\";})(),(function fuck(){return \"IRn\";})(" ascii
    $s16 = "tion fuck(){return \"IPu\";})(),(function fuck(){return \"Ot\";})(),(function fuck(){return \"Qh\";})(),(function fuck(){return " ascii
    $s17 = "n \"Vb\";})(),(function fuck(){return \"UOe\";})(),(function fuck(){return \"Jo\";})(),(function fuck(){return \"IRn\";})(),(fun" ascii
    $s18 = "nction fuck(){return \"TTs\";})(),(function fuck(){return \"Vb\";})(),(function fuck(){return \"ADy\";})(),(function fuck(){retu" ascii
    $s19 = "n fuck(){return \"IPu\";})(),(function fuck(){return \"XHj\";})(),(function fuck(){return \"Py\";})(),(function fuck(){return \"" ascii
    $s20 = "uck(){return \"DRx\";})(),(function fuck(){return \"IPu\";})(),(function fuck(){return \"ZLd\";})(),(function fuck(){return \"IO" ascii

  condition:
    (uint16(0) == 0x2f0a and (8 of them)
    ) or (all of them)
}