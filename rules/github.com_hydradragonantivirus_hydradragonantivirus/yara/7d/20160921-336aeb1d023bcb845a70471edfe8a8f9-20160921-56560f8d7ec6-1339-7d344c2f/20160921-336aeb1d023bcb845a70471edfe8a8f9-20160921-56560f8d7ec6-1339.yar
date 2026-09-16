rule _20160921_336aeb1d023bcb845a70471edfe8a8f9_20160921_56560f8d7ec6_1339 {
  meta:
    description = "datamaliciousorder - from files 20160921_336aeb1d023bcb845a70471edfe8a8f9.js, 20160921_56560f8d7ec61c150afb741a4a7975e2.js, 20160921_65ff2a70ce98d58243fbbdf4849b9c40.js, 20160921_766f6fcbd2a94a55747a3f5b9a204b0e.js, 20160921_885a9e110f52f3ca103e4718673adb3b.js, 20160921_9ab244a7866dc1a3d98006482dd7da38.js, 20160921_bd4d87f94769a02253ed6ac2e747557f.js, 20160921_dcd6ef8585af301daafce3419ba14724.js, 20160921_ef83849d63779003debb3d7ec32b193e.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "f77fe3497bb26b47e909d597cb0055c997e8149b22c878594ee85d0303c27381"
    hash2       = "ba922e4e746eb45b8e98a88ec3071072c0850dbd5e2a359302331e1ae65210fb"
    hash3       = "4be01014513bc9c23e14a62953fb7d9f955467208a844109b10c685b1f9c4f29"
    hash4       = "7ac34bd929ce60a874936fef08adcce78783c70441a9eff1cd392604bcf45ff7"
    hash5       = "a777a2e324ff6d64746b42793d888cea6f2beec30ded4165b5b13eda473e58bf"
    hash6       = "99692f93901b579e0992cf6f44c274569bb1257cf12f2eebf5baceb7cb31d6af"
    hash7       = "de567d209b0d4353173c2f3ae63037edd6f5695cc5edcdba1dba29b422d963ac"
    hash8       = "599a5b97cea2145a98305cb09031a146a6d64c54509328df8783368c3a3ba008"
    hash9       = "8c488afd3d971ee89eb15305d884bacb01b91fa70760bea0aaf808120622dfa3"

  strings:
    $s1  = "Ar\";})(),(function fuck(){return \"Xg\";})(),(function fuck(){return \"UXf\";})(),(function fuck(){return \"KVh\";})(),(functio" ascii
    $s2  = "})(),(function fuck(){return \"IPu\";})(),(function fuck(){return \"GWo\";})(),(function fuck(){return \"Na\";})(),(function fuc" ascii
    $s3  = "n fuck(){return \"CCb\";})(),(function fuck(){return \"Na\";})(),(function fuck(){return \"LGo\";})(),(function fuck(){return \"" ascii
    $s4  = "tion fuck(){return \"ZVi\";})(),(function fuck(){return \"IPu\";})(),(function fuck(){return \"MBg\";})(),(function fuck(){retur" ascii
    $s5  = "turn \"Xw\";})(),(function fuck(){return \"XHj\";})(),(function fuck(){return \"Fv\";})(),(function fuck(){return \"Za\";})(),(f" ascii
    $s6  = "){return \"Za\";})(),(function fuck(){return \"IPu\";})(),(function fuck(){return \"XCr\";})(),(function fuck(){return \"Na\";})" ascii
    $s7  = "uck(){return \"Jo\";})(),(function fuck(){return \"KVh\";})(),(function fuck(){return \"Vb\";})(),(function fuck(){return \"IPu" ascii
    $s8  = "uck(){return \"Xg\";})(),(function fuck(){return \"Ik\";})(),(function fuck(){return \"Sx\";})(),(function fuck(){return \"Xw\";" ascii
    $s9  = "),(function fuck(){return \"Ot\";})(),(function fuck(){return \"AUx\";})(),(function fuck(){return \"Np\";})(),(function fuck(){" ascii
    $s10 = "urn \"Za\";})(),(function fuck(){return \"IPu\";})(),(function fuck(){return \"Yk\";})(),(function fuck(){return \"Py\";})(),(fu" ascii
    $s11 = "\";})(),(function fuck(){return \"Xw\";})(),(function fuck(){return \"Jo\";})(),(function fuck(){return \"Xw\";})(),(function fu" ascii
    $s12 = ";})(),(function fuck(){return \"Wo0\";})(),(function fuck(){return \"XFd\";})(),(function fuck(){return \"Pc\";})(),(function fu" ascii
    $s13 = "(),(function fuck(){return \"Ot\";})(),(function fuck(){return \"Jh\";})(),(function fuck(){return \"IPu\";})(),(function fuck()" ascii
    $s14 = "\"IPu\";})(),(function fuck(){return \"We\";})(),(function fuck(){return \"YQt\";})(),(function fuck(){return \"Jg\";})(),(funct" ascii
    $s15 = "){return \"Za\";})(),(function fuck(){return \"IPu\";})(),(function fuck(){return \"Hs\";})(),(function fuck(){return \"Wo0\";})" ascii

  condition:
    (uint16(0) == 0x2f0a and (8 of them)
    ) or (all of them)
}