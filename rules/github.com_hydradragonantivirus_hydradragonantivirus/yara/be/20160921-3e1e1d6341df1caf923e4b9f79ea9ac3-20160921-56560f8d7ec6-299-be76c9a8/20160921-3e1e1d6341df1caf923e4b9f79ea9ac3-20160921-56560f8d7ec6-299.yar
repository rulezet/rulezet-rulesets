rule _20160921_3e1e1d6341df1caf923e4b9f79ea9ac3_20160921_56560f8d7ec6_299 {
  meta:
    description = "datamaliciousorder - from files 20160921_3e1e1d6341df1caf923e4b9f79ea9ac3.js, 20160921_56560f8d7ec61c150afb741a4a7975e2.js, 20160921_e3aa4388897e55faa45b78b5304a0796.js, 20160921_ef83849d63779003debb3d7ec32b193e.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "d858d56d343b97488263af92c96b6bee8f8213dd2aec4d79132b57f04ea3c568"
    hash2       = "ba922e4e746eb45b8e98a88ec3071072c0850dbd5e2a359302331e1ae65210fb"
    hash3       = "2891f4105f11c496e2a838e51e47950b803da8c03fe0cd132c2ad23839c0ca37"
    hash4       = "8c488afd3d971ee89eb15305d884bacb01b91fa70760bea0aaf808120622dfa3"

  strings:
    $s1  = "ck(){return \"Cd\";})(),(function fuck(){return \"IPu\";})(),(function fuck(){return \"IKv\";})(),(function fuck(){return \"IPu" ascii
    $s2  = "ction fuck(){return \"TTs\";})(),(function fuck(){return \"LGo\";})(),(function fuck(){return \"RAi\";})(),(function fuck(){retu" ascii
    $s3  = " fuck(){return \"PDf\";})(),(function fuck(){return \"Cd\";})(),(function fuck(){return \"PDf\";})(),(function fuck(){return \"U" ascii
    $s4  = "fuck(){return \"ADy\";})(),(function fuck(){return \"Vb\";})(),(function fuck(){return \"IRn\";})(),(function fuck(){return \"MB" ascii
    $s5  = "turn \"Ai\";})(),(function fuck(){return \"QTc\";})(),(function fuck(){return \"UOe\";})(),(function fuck(){return \"IPu\";})()," ascii
    $s6  = "on fuck(){return \"Cd\";})(),(function fuck(){return \"GNm\";})(),(function fuck(){return \"UOe\";})(),(function fuck(){return " ascii
    $s7  = ";})(),(function fuck(){return \"Vf\";})(),(function fuck(){return \"EHo\";})(),(function fuck(){return \"IRn\";})(),(function fu" ascii
    $s8  = "k(){return \"MBg\";})(),(function fuck(){return \"Vb\";})(),(function fuck(){return \"ADy\";})(),(function fuck(){return \"GNm\"" ascii
    $s9  = "IPu\";})(),(function fuck(){return \"USf\";})(),(function fuck(){return \"Cd\";})(),(function fuck(){return \"ADy\";})(),(functi" ascii
    $s10 = "ck(){return \"TTs\";})(),(function fuck(){return \"Vb\";})(),(function fuck(){return \"PDf\";})(),(function fuck(){return \"UOe" ascii
    $s11 = "rn \"IPu\";})(),(function fuck(){return \"UOe\";})(),(function fuck(){return \"Cd\";})(),(function fuck(){return \"Cd\";})(),(fu" ascii
    $s12 = "n \"IKv\";})(),(function fuck(){return \"RAi\";})(),(function fuck(){return \"LGo\";})(),(function fuck(){return \"PDf\";})(),(f" ascii
    $s13 = "ction fuck(){return \"IKv\";})(),(function fuck(){return \"IPu\";})(),(function fuck(){return \"Np\";})(),(function fuck(){retur" ascii
    $s14 = "{return \"PDf\";})(),(function fuck(){return \"USf\";})(),(function fuck(){return \"NKq\";})(),(function fuck(){return \"Ug\";})" ascii
    $s15 = "eturn \"Vb\";})(),(function fuck(){return \"Np\";})(),(function fuck(){return \"PDf\";})(),(function fuck(){return \"NKq\";})()," ascii
    $s16 = "n fuck(){return \"PDf\";})(),(function fuck(){return \"RAi\";})(),(function fuck(){return \"Np\";})(),(function fuck(){return \"" ascii
    $s17 = "),(function fuck(){return \"LGo\";})(),(function fuck(){return \"GNm\";})(),(function fuck(){return \"Np\";})(),(function fuck()" ascii
    $s18 = "(function fuck(){return \"UOe\";})(),(function fuck(){return \"UOe\";})(),(function fuck(){return \"ADy\";})(),(function fuck(){" ascii
    $s19 = "rn \"USf\";})(),(function fuck(){return \"Cd\";})(),(function fuck(){return \"UOe\";})(),(function fuck(){return \"NKq\";})(),(f" ascii
    $s20 = "tion fuck(){return \"DRx\";})(),(function fuck(){return \"IPu\";})(),(function fuck(){return \"UOe\";})(),(function fuck(){retur" ascii

  condition:
    (uint16(0) == 0x2f0a and (8 of them)
    ) or (all of them)
}