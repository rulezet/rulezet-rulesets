rule _20160921_5ed9729c3ab2cb9d37d8a088af1aba59_20160921_b74bfd3dc740_5268 {
  meta:
    description = "datamaliciousorder - from files 20160921_5ed9729c3ab2cb9d37d8a088af1aba59.js, 20160921_b74bfd3dc7404d3d5a6512718aa52504.js, 20160921_dc73cfa7a33eb762f38614c69a95919d.js, 20160921_fa8c93ef210d8b4c6831cb1425f1dc9b.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "c5908838424a9cae8eb5587cff7048056b427db1deb512dcbe9ca852a402e03d"
    hash2       = "359d333ab8fc51d27349ecaec71f8baf8e8aafae5bfe2d6afd26f4ed76e802db"
    hash3       = "50e80269adbbca38f500219eaf7cec16f396b3d8a7c56d342b2e4839819ea598"
    hash4       = "7e7bb1d2ade80c23d5462f8e4a470a3c3245b07b8a709a3c911ff76a8c32da35"

  strings:
    $s1 = "Pu\";})(),(function fuck(){return \"Ve\";})(),(function fuck(){return \"UXf\";})(),(function fuck(){return \"LGo\";})(),(functio" ascii
    $s2 = "){return \"MBg\";})(),(function fuck(){return \"Xw\";})(),(function fuck(){return \"Xw\";})(),(function fuck(){return \"NKq\";})" ascii
    $s3 = "return \"DWe\";})(),(function fuck(){return \"Dc\";})(),(function fuck(){return \"LGo\";})(),(function fuck(){return \"MBg\";})(" ascii
    $s4 = " fuck(){return \"NKq\";})(),(function fuck(){return \"IPu\";})(),(function fuck(){return \"ZVi\";})(),(function fuck(){return \"" ascii
    $s5 = "{return \"BGe\";})(),(function fuck(){return \"IPu\";})(),(function fuck(){return \"LGo\";})(),(function fuck(){return \"USf\";}" ascii

  condition:
    (uint16(0) == 0x2f0a and (all of them)
    ) or (all of them)
}