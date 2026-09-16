rule _20160921_41f7b3abc606ff1ddad7593361eaa449_20160921_69a85efe2b4b_5040 {
  meta:
    description = "datamaliciousorder - from files 20160921_41f7b3abc606ff1ddad7593361eaa449.js, 20160921_69a85efe2b4b34254269f0f82213bf2c.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "53e06a7234c6522ba26a61e46d13312e1063594b0e33bec9fae49d2dc4b77c28"
    hash2       = "8def27dca1738a7df5978549903a2c809fcb8a8d158e5de122afc54ad2dd3dea"

  strings:
    $s1 = " \"Ve\";})(),(function fuck(){return \"MUs\";})(),(function fuck(){return \"RAi\";})(),(function fuck(){return \"IPu\";})(),(fun" ascii
    $s2 = "n \"LGo\";})(),(function fuck(){return \"Vb\";})(),(function fuck(){return \"LGo\";})(),(function fuck(){return \"NKq\";})(),(fu" ascii
    $s3 = "eturn \"Oh\";})(),(function fuck(){return \"Xg\";})(),(function fuck(){return \"MBg\";})(),(function fuck(){return \"Vb\";})(),(" ascii
    $s4 = "\"XHj\";})(),(function fuck(){return \"KVh\";})(),(function fuck(){return \"IPu\";})(),(function fuck(){return \"MBg\";})(),(fun" ascii
    $s5 = " fuck(){return \"LGo\";})(),(function fuck(){return \"Vb\";})(),(function fuck(){return \"USf\";})(),(function fuck(){return \"I" ascii

  condition:
    (uint16(0) == 0x2f0a and (all of them)
    ) or (all of them)
}