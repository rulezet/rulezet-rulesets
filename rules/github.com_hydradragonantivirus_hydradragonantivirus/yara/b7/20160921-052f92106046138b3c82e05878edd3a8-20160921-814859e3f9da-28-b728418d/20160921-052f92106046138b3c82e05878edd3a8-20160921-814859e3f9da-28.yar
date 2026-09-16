rule _20160921_052f92106046138b3c82e05878edd3a8_20160921_814859e3f9da_28 {
  meta:
    description = "datamaliciousorder - from files 20160921_052f92106046138b3c82e05878edd3a8.js, 20160921_814859e3f9dab39a18edf940d1dd5650.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "4812ea00b657b288e9ad51c72fcf466179e82a552fa3278fa9a896cc053c9fdc"
    hash2       = "c61c4f66b5cb5b5fa606db7d7b914cbb3fe4d8f1b8ae72ca6b16b707c575cfb0"

  strings:
    $s1  = "nction fuck(){return \"IPu\";})(),(function fuck(){return \"LGo\";})(),(function fuck(){return \"Hs\";})(),(function fuck(){retu" ascii
    $s2  = "n \"GWo\";})(),(function fuck(){return \"Wo0\";})(),(function fuck(){return \"DRx\";})(),(function fuck(){return \"XHj\";})(),(f" ascii
    $s3  = "\"Za\";})(),(function fuck(){return \"IPu\";})(),(function fuck(){return \"Nm\";})(),(function fuck(){return \"Ug\";})(),(functi" ascii
    $s4  = "TTs\";})(),(function fuck(){return \"Cd\";})(),(function fuck(){return \"Za\";})(),(function fuck(){return \"RAi\";})(),(functio" ascii
    $s5  = "s\";})(),(function fuck(){return \"ADy\";})(),(function fuck(){return \"DRx\";})(),(function fuck(){return \"XHj\";})(),(functio" ascii
    $s6  = "turn \"QTc\";})(),(function fuck(){return \"TTs\";})(),(function fuck(){return \"YQt\";})(),(function fuck(){return \"ZLd\";})()" ascii
    $s7  = " \"Xw\";})(),(function fuck(){return \"Dc\";})(),(function fuck(){return \"UXf\";})(),(function fuck(){return \"Fv\";})(),(funct" ascii
    $s8  = "TTs\";})(),(function fuck(){return \"ADy\";})(),(function fuck(){return \"Np\";})(),(function fuck(){return \"Jo\";})(),(functio" ascii
    $s9  = "n fuck(){return \"Dc\";})(),(function fuck(){return \"LGo\";})(),(function fuck(){return \"OQr\";})(),(function fuck(){return \"" ascii
    $s10 = "g\";})(),(function fuck(){return \"Jh\";})(),(function fuck(){return \"NKq\";})(),(function fuck(){return \"IPu\";})(),(function" ascii
    $s11 = "Bg\";})(),(function fuck(){return \"AUx\";})(),(function fuck(){return \"ZWu\";})(),(function fuck(){return \"FJs\";})(),(functi" ascii
    $s12 = "(function fuck(){return \"TTs\";})(),(function fuck(){return \"DWe\";})(),(function fuck(){return \"Ik\";})(),(function fuck(){r" ascii
    $s13 = " fuck(){return \"OPz\";})(),(function fuck(){return \"IPu\";})(),(function fuck(){return \"Ve\";})(),(function fuck(){return \"Q" ascii
    $s14 = " fuck(){return \"Sx\";})(),(function fuck(){return \"UOe\";})(),(function fuck(){return \"TTs\";})(),(function fuck(){return \"X" ascii
    $s15 = "unction fuck(){return \"MBg\";})(),(function fuck(){return \"Vb\";})(),(function fuck(){return \"UOe\";})(),(function fuck(){ret" ascii
    $s16 = "return \"Jh\";})(),(function fuck(){return \"Pc\";})(),(function fuck(){return \"ZWu\";})(),(function fuck(){return \"Na\";})()," ascii
    $s17 = "n fuck(){return \"DRx\";})(),(function fuck(){return \"XCr\";})(),(function fuck(){return \"Ot\";})(),(function fuck(){return \"" ascii
    $s18 = ",(function fuck(){return \"TTs\";})(),(function fuck(){return \"LGo\";})(),(function fuck(){return \"Jh\";})(),(function fuck(){" ascii
    $s19 = "(){return \"IPu\";})(),(function fuck(){return \"Wo\";})(),(function fuck(){return \"Ug\";})(),(function fuck(){return \"EHo\";}" ascii
    $s20 = "n \"Nm\";})(),(function fuck(){return \"Nm\";})(),(function fuck(){return \"Nm\";})(),(function fuck(){return \"Nm\";})(),(funct" ascii

  condition:
    (uint16(0) == 0x2f0a and (8 of them)
    ) or (all of them)
}