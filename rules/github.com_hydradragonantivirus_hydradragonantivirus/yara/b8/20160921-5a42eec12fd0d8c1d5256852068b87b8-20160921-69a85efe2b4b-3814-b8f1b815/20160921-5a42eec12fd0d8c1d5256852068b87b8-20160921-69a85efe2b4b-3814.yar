rule _20160921_5a42eec12fd0d8c1d5256852068b87b8_20160921_69a85efe2b4b_3814 {
  meta:
    description = "datamaliciousorder - from files 20160921_5a42eec12fd0d8c1d5256852068b87b8.js, 20160921_69a85efe2b4b34254269f0f82213bf2c.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "54a7451a184fd8afa3cac9d787d5f83abeb8fecd14d9f136cff135e9f0d849e0"
    hash2       = "8def27dca1738a7df5978549903a2c809fcb8a8d158e5de122afc54ad2dd3dea"

  strings:
    $s1 = "uck(){return \"Wo0\";})(),(function fuck(){return \"GWo\";})(),(function fuck(){return \"MOj\";})(),(function fuck(){return \"NK" ascii
    $s2 = "\"CTm\";})(),(function fuck(){return \"We\";})(),(function fuck(){return \"ZVi\";})(),(function fuck(){return \"TTs\";})(),(func" ascii
    $s3 = ";})(),(function fuck(){return \"CTm\";})(),(function fuck(){return \"CTm\";})(),(function fuck(){return \"Et\";})(),(function fu" ascii
    $s4 = "eturn \"AUx\";})(),(function fuck(){return \"AUx\";})(),(function fuck(){return \"LGo\";})(),(function fuck(){return \"NKq\";})(" ascii
    $s5 = "turn \"AUx\";})(),(function fuck(){return \"UOe\";})(),(function fuck(){return \"IRn\";})(),(function fuck(){return \"MBg\";})()" ascii
    $s6 = ";})(),(function fuck(){return \"Np\";})(),(function fuck(){return \"AUx\";})(),(function fuck(){return \"NKq\";})(),(function fu" ascii

  condition:
    (uint16(0) == 0x2f0a and (all of them)
    ) or (all of them)
}