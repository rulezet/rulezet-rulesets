rule _20160921_3e1e1d6341df1caf923e4b9f79ea9ac3_20160921_56560f8d7ec6_5013 {
  meta:
    description = "datamaliciousorder - from files 20160921_3e1e1d6341df1caf923e4b9f79ea9ac3.js, 20160921_56560f8d7ec61c150afb741a4a7975e2.js, 20160921_8be5b3aac0a2f47acb168b56c6f880bf.js, 20160921_ef83849d63779003debb3d7ec32b193e.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "d858d56d343b97488263af92c96b6bee8f8213dd2aec4d79132b57f04ea3c568"
    hash2       = "ba922e4e746eb45b8e98a88ec3071072c0850dbd5e2a359302331e1ae65210fb"
    hash3       = "344d7dd8865545f9f4c1045a85547b4140c66621aeedeb02bf60ff4598ff6930"
    hash4       = "8c488afd3d971ee89eb15305d884bacb01b91fa70760bea0aaf808120622dfa3"

  strings:
    $s1 = "nction fuck(){return \"MBg\";})(),(function fuck(){return \"Hs\";})(),(function fuck(){return \"YAv\";})(),(function fuck(){retu" ascii
    $s2 = "(){return \"IPu\";})(),(function fuck(){return \"YQt\";})(),(function fuck(){return \"Ve\";})(),(function fuck(){return \"IRn\";" ascii
    $s3 = "GWo\";})(),(function fuck(){return \"Ik\";})(),(function fuck(){return \"IPu\";})(),(function fuck(){return \"DRx\";})(),(functi" ascii
    $s4 = "turn \"Sx\";})(),(function fuck(){return \"IPu\";})(),(function fuck(){return \"DHd\";})(),(function fuck(){return \"Ml\";})(),(" ascii
    $s5 = ")(),(function fuck(){return \"IRn\";})(),(function fuck(){return \"MBg\";})(),(function fuck(){return \"DWe\";})(),(function fuc" ascii

  condition:
    (uint16(0) == 0x2f0a and (all of them)
    ) or (all of them)
}