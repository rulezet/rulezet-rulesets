rule _20160921_511769d99fbe4d59a2e55781fb0eb77c_20160921_b2419a000449_1723 {
  meta:
    description = "datamaliciousorder - from files 20160921_511769d99fbe4d59a2e55781fb0eb77c.js, 20160921_b2419a000449b12cbd6aff3732baf55d.js, 20160921_cda776f6c5cb6eec510c00d5294fbfae.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "2f4a69b097fb3d0d29d7f041be11cd2e8af137bd0ed525674079a1b7de28c7fd"
    hash2       = "ea7b5520c177b4adf74565706c3c8ed38eed94f30b6927b0ceb647f7f768a2b5"
    hash3       = "064df16cff12584bccc68fb79fe80908e6edeb4ccf32c3c0b6a79b8b0424820c"

  strings:
    $s1  = ";})(),(function fuck(){return \"Dc\";})(),(function fuck(){return \"OQr\";})(),(function fuck(){return \"CCb\";})(),(function fu" ascii
    $s2  = "(){return \"IPu\";})(),(function fuck(){return \"LGo\";})(),(function fuck(){return \"USf\";})(),(function fuck(){return \"GNm\"" ascii
    $s3  = "ion fuck(){return \"IPu\";})(),(function fuck(){return \"LGo\";})(),(function fuck(){return \"Cd\";})(),(function fuck(){return " ascii
    $s4  = "Za\";})(),(function fuck(){return \"IRn\";})(),(function fuck(){return \"IPu\";})(),(function fuck(){return \"BGe\";})(),(functi" ascii
    $s5  = "){return \"Ai\";})(),(function fuck(){return \"Za\";})(),(function fuck(){return \"IRn\";})(),(function fuck(){return \"IPu\";})" ascii
    $s6  = "eturn \"IOs\";})(),(function fuck(){return \"PDf\";})(),(function fuck(){return \"MOj\";})(),(function fuck(){return \"NKq\";})(" ascii
    $s7  = "n fuck(){return \"MBg\";})(),(function fuck(){return \"Ai\";})(),(function fuck(){return \"Na\";})(),(function fuck(){return \"V" ascii
    $s8  = "tion fuck(){return \"LGo\";})(),(function fuck(){return \"MBg\";})(),(function fuck(){return \"Ot\";})(),(function fuck(){return" ascii
    $s9  = "IPu\";})(),(function fuck(){return \"OQr\";})(),(function fuck(){return \"GJx\";})(),(function fuck(){return \"Nm\";})(),(functi" ascii
    $s10 = "b\";})(),(function fuck(){return \"GNm\";})(),(function fuck(){return \"LGo\";})(),(function fuck(){return \"Cd\";})(),(function" ascii
    $s11 = "turn \"Vb\";})(),(function fuck(){return \"GNm\";})(),(function fuck(){return \"LGo\";})(),(function fuck(){return \"Cd\";})(),(" ascii

  condition:
    (uint16(0) == 0x2f0a and (8 of them)
    ) or (all of them)
}