rule _20160921_3b2083afdb57ae7e611f6f42c6787c73_20160921_acea633b7398_4982 {
  meta:
    description = "datamaliciousorder - from files 20160921_3b2083afdb57ae7e611f6f42c6787c73.js, 20160921_acea633b73985995ce9764bf94db0972.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "4c81783a1510b3172e1702365554b0e2000709a4e4217a8970aa381c9b357e36"
    hash2       = "dd77df78b3a755b016a27bbcac8fe7c015ab04472e2ca2d2d9aa476befb3148a"

  strings:
    $s1 = "{return \"AUx\";})(),(function fuck(){return \"LGo\";})(),(function fuck(){return \"IPu\";})(),(function fuck(){return \"DRx\";}" ascii
    $s2 = " fuck(){return \"Za\";})(),(function fuck(){return \"IPu\";})(),(function fuck(){return \"Hs\";})(),(function fuck(){return \"Wo" ascii
    $s3 = "ction fuck(){return \"LGo\";})(),(function fuck(){return \"Vb\";})(),(function fuck(){return \"GNm\";})(),(function fuck(){retur" ascii
    $s4 = " \"Vb\";})(),(function fuck(){return \"GNm\";})(),(function fuck(){return \"GNm\";})(),(function fuck(){return \"MOj\";})(),(fun" ascii
    $s5 = "ion fuck(){return \"ZVi\";})(),(function fuck(){return \"MBg\";})(),(function fuck(){return \"Oh\";})(),(function fuck(){return " ascii

  condition:
    (uint16(0) == 0x2f0a and (all of them)
    ) or (all of them)
}