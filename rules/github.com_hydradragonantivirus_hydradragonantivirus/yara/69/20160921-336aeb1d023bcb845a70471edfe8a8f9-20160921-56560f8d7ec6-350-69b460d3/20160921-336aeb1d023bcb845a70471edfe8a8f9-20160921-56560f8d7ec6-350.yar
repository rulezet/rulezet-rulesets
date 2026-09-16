rule _20160921_336aeb1d023bcb845a70471edfe8a8f9_20160921_56560f8d7ec6_350 {
  meta:
    description = "datamaliciousorder - from files 20160921_336aeb1d023bcb845a70471edfe8a8f9.js, 20160921_56560f8d7ec61c150afb741a4a7975e2.js, 20160921_65ff2a70ce98d58243fbbdf4849b9c40.js, 20160921_885a9e110f52f3ca103e4718673adb3b.js, 20160921_9ab244a7866dc1a3d98006482dd7da38.js, 20160921_ef83849d63779003debb3d7ec32b193e.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "f77fe3497bb26b47e909d597cb0055c997e8149b22c878594ee85d0303c27381"
    hash2       = "ba922e4e746eb45b8e98a88ec3071072c0850dbd5e2a359302331e1ae65210fb"
    hash3       = "4be01014513bc9c23e14a62953fb7d9f955467208a844109b10c685b1f9c4f29"
    hash4       = "a777a2e324ff6d64746b42793d888cea6f2beec30ded4165b5b13eda473e58bf"
    hash5       = "99692f93901b579e0992cf6f44c274569bb1257cf12f2eebf5baceb7cb31d6af"
    hash6       = "8c488afd3d971ee89eb15305d884bacb01b91fa70760bea0aaf808120622dfa3"

  strings:
    $s1  = " fuck(){return \"Za\";})(),(function fuck(){return \"IPu\";})(),(function fuck(){return \"Qh\";})(),(function fuck(){return \"Hs" ascii
    $s2  = "unction fuck(){return \"DWe\";})(),(function fuck(){return \"Dc\";})(),(function fuck(){return \"Xw\";})(),(function fuck(){retu" ascii
    $s3  = "turn \"Za\";})(),(function fuck(){return \"EHo\";})(),(function fuck(){return \"UXf\";})(),(function fuck(){return \"KVh\";})()," ascii
    $s4  = "n fuck(){return \"Ai\";})(),(function fuck(){return \"Jh\";})(),(function fuck(){return \"GNm\";})(),(function fuck(){return \"I" ascii
    $s5  = "tion fuck(){return \"Pc\";})(),(function fuck(){return \"Fv\";})(),(function fuck(){return \"Xw\";})(),(function fuck(){return " ascii
    $s6  = " fuck(){return \"Za\";})(),(function fuck(){return \"IPu\";})(),(function fuck(){return \"ZWu\";})(),(function fuck(){return \"V" ascii
    $s7  = ",(function fuck(){return \"Xw\";})(),(function fuck(){return \"Xg\";})(),(function fuck(){return \"ZWu\";})(),(function fuck(){r" ascii
    $s8  = "ck(){return \"Wn\";})(),(function fuck(){return \"XHj\";})(),(function fuck(){return \"Jg\";})(),(function fuck(){return \"Ar\";" ascii
    $s9  = "ction fuck(){return \"Pc\";})(),(function fuck(){return \"Xg\";})(),(function fuck(){return \"Na\";})(),(function fuck(){return " ascii
    $s10 = " \"Za\";})(),(function fuck(){return \"IPu\";})(),(function fuck(){return \"Ot\";})(),(function fuck(){return \"MIl\";})(),(func" ascii
    $s11 = "return \"Za\";})(),(function fuck(){return \"IPu\";})(),(function fuck(){return \"Wo0\";})(),(function fuck(){return \"Xg\";})()" ascii
    $s12 = " fuck(){return \"Za\";})(),(function fuck(){return \"IPu\";})(),(function fuck(){return \"ZLd\";})(),(function fuck(){return \"H" ascii
    $s13 = "a\";})(),(function fuck(){return \"IPu\";})(),(function fuck(){return \"GJx\";})(),(function fuck(){return \"XFd\";})(),(functio" ascii
    $s14 = "unction fuck(){return \"Xw\";})(),(function fuck(){return \"YAv\";})(),(function fuck(){return \"Xg\";})(),(function fuck(){retu" ascii
    $s15 = "nction fuck(){return \"Oh\";})(),(function fuck(){return \"XCr\";})(),(function fuck(){return \"Oh\";})(),(function fuck(){retur" ascii
    $s16 = "uck(){return \"IPu\";})(),(function fuck(){return \"Wo0\";})(),(function fuck(){return \"Av\";})(),(function fuck(){return \"GNm" ascii
    $s17 = "\";})(),(function fuck(){return \"Cd\";})(),(function fuck(){return \"Wn\";})(),(function fuck(){return \"Wn\";})(),(function fu" ascii
    $s18 = "(function fuck(){return \"IPu\";})(),(function fuck(){return \"Nm\";})(),(function fuck(){return \"Za\";})(),(function fuck(){re" ascii
    $s19 = "function fuck(){return \"Hs\";})(),(function fuck(){return \"SUi\";})(),(function fuck(){return \"PDf\";})(),(function fuck(){re" ascii
    $s20 = "ion fuck(){return \"Xw\";})(),(function fuck(){return \"Ik\";})(),(function fuck(){return \"Fv\";})(),(function fuck(){return \"" ascii

  condition:
    (uint16(0) == 0x2f0a and (8 of them)
    ) or (all of them)
}