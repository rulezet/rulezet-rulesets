rule _20160921_06a7c56eaf19048ede06f33b655f2bc5_20160921_69a85efe2b4b_4274 {
  meta:
    description = "datamaliciousorder - from files 20160921_06a7c56eaf19048ede06f33b655f2bc5.js, 20160921_69a85efe2b4b34254269f0f82213bf2c.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "3971833c2ab49de293c47181e999db88e5cad0eaddc5aa38a2516eeac1cab29d"
    hash2       = "8def27dca1738a7df5978549903a2c809fcb8a8d158e5de122afc54ad2dd3dea"

  strings:
    $s1 = "tion fuck(){return \"IRn\";})(),(function fuck(){return \"OQr\";})(),(function fuck(){return \"Nm\";})(),(function fuck(){return" ascii
    $s2 = "0\";})(),(function fuck(){return \"XCr\";})(),(function fuck(){return \"EHo\";})(),(function fuck(){return \"IPu\";})(),(functio" ascii
    $s3 = "turn \"TTs\";})(),(function fuck(){return \"AUx\";})(),(function fuck(){return \"RAi\";})(),(function fuck(){return \"UOe\";})()" ascii
    $s4 = "on fuck(){return \"AUx\";})(),(function fuck(){return \"LGo\";})(),(function fuck(){return \"IPu\";})(),(function fuck(){return " ascii
    $s5 = "turn \"DRx\";})(),(function fuck(){return \"IPu\";})(),(function fuck(){return \"AUx\";})(),(function fuck(){return \"AUx\";})()" ascii

  condition:
    (uint16(0) == 0x2f0a and (all of them)
    ) or (all of them)
}