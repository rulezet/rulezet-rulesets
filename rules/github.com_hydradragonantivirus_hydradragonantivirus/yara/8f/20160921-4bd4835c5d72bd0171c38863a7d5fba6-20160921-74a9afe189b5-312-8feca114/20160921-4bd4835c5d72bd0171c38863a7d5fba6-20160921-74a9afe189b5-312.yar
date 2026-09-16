rule _20160921_4bd4835c5d72bd0171c38863a7d5fba6_20160921_74a9afe189b5_312 {
  meta:
    description = "datamaliciousorder - from files 20160921_4bd4835c5d72bd0171c38863a7d5fba6.js, 20160921_74a9afe189b59f0b8148a7f92f42b125.js, 20160921_82c6439487239a08e403c18f347e12e6.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "34fcd9c1543d39dfd57d9c09da7c6123934388bbc0bf645db2a4dae174f514cc"
    hash2       = "5ce6bfd72ee0a8f8259b2cfbaa6f5b49ec72ab64b03caf4bd2a4f733ef96925b"
    hash3       = "db301ab72cd18ad4198865983d8e64e1840325c04d40cacaa8f5e2097faee094"

  strings:
    $s1  = "nction fuck(){return \"GNm\";})(),(function fuck(){return \"Vb\";})(),(function fuck(){return \"IPu\";})(),(function fuck(){retu" ascii
    $s2  = "),(function fuck(){return \"ADy\";})(),(function fuck(){return \"Vb\";})(),(function fuck(){return \"Vb\";})(),(function fuck(){" ascii
    $s3  = "Go\";})(),(function fuck(){return \"USf\";})(),(function fuck(){return \"Cd\";})(),(function fuck(){return \"IPu\";})(),(functio" ascii
    $s4  = "turn \"DRx\";})(),(function fuck(){return \"IPu\";})(),(function fuck(){return \"LGo\";})(),(function fuck(){return \"ADy\";})()" ascii
    $s5  = "k(){return \"GNm\";})(),(function fuck(){return \"GNm\";})(),(function fuck(){return \"IPu\";})(),(function fuck(){return \"IKv" ascii
    $s6  = "nction fuck(){return \"DRx\";})(),(function fuck(){return \"IPu\";})(),(function fuck(){return \"Cd\";})(),(function fuck(){retu" ascii
    $s7  = "n fuck(){return \"Cd\";})(),(function fuck(){return \"Vb\";})(),(function fuck(){return \"GNm\";})(),(function fuck(){return \"U" ascii
    $s8  = "nction fuck(){return \"ADy\";})(),(function fuck(){return \"GNm\";})(),(function fuck(){return \"Vb\";})(),(function fuck(){retu" ascii
    $s9  = "ction fuck(){return \"XHj\";})(),(function fuck(){return \"YAv\";})(),(function fuck(){return \"IPu\";})(),(function fuck(){retu" ascii
    $s10 = "fuck(){return \"TTs\";})(),(function fuck(){return \"Vb\";})(),(function fuck(){return \"RAi\";})(),(function fuck(){return \"Np" ascii
    $s11 = "MBg\";})(),(function fuck(){return \"LGo\";})(),(function fuck(){return \"Cd\";})(),(function fuck(){return \"Vb\";})(),(functio" ascii
    $s12 = ";})(),(function fuck(){return \"Cd\";})(),(function fuck(){return \"ADy\";})(),(function fuck(){return \"IRn\";})(),(function fu" ascii
    $s13 = "turn \"IKv\";})(),(function fuck(){return \"Np\";})(),(function fuck(){return \"Vb\";})(),(function fuck(){return \"ADy\";})(),(" ascii
    $s14 = "){return \"RAi\";})(),(function fuck(){return \"GNm\";})(),(function fuck(){return \"USf\";})(),(function fuck(){return \"IRn\";" ascii
    $s15 = "tion fuck(){return \"LGo\";})(),(function fuck(){return \"GNm\";})(),(function fuck(){return \"IPu\";})(),(function fuck(){retur" ascii
    $s16 = "urn \"GNm\";})(),(function fuck(){return \"IPu\";})(),(function fuck(){return \"Yb\";})(),(function fuck(){return \"IPu\";})(),(" ascii
    $s17 = "rn \"Vb\";})(),(function fuck(){return \"Cd\";})(),(function fuck(){return \"PDf\";})(),(function fuck(){return \"IRn\";})(),(fu" ascii
    $s18 = "})(),(function fuck(){return \"Cd\";})(),(function fuck(){return \"LGo\";})(),(function fuck(){return \"IPu\";})(),(function fuc" ascii
    $s19 = "Go\";})(),(function fuck(){return \"PDf\";})(),(function fuck(){return \"Vb\";})(),(function fuck(){return \"GNm\";})(),(functio" ascii
    $s20 = "turn \"PDf\";})(),(function fuck(){return \"Vb\";})(),(function fuck(){return \"LGo\";})(),(function fuck(){return \"GNm\";})()," ascii

  condition:
    (uint16(0) == 0x2f0a and (8 of them)
    ) or (all of them)
}