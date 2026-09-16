rule _20160921_3a789c5184fa2a259b72c0ebaa255c10_20160921_bd3b4c7cf058_114 {
  meta:
    description = "datamaliciousorder - from files 20160921_3a789c5184fa2a259b72c0ebaa255c10.js, 20160921_bd3b4c7cf0588af7c4014d66947dd198.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "db17c9f665e5fe0e02b03fbde1c9c388c4600d6d7ec9c3890464b11ceab9fc9d"
    hash2       = "b6d0dad910056c72d41faa066846061b7a1630e389a231f1b551dd9947342637"

  strings:
    $s1  = "return \"Py\";})(),(function fuck(){return \"MBg\";})(),(function fuck(){return \"Nm\";})(),(function fuck(){return \"ZWu\";})()" ascii
    $s2  = "IPu\";})(),(function fuck(){return \"Xw\";})(),(function fuck(){return \"Xg\";})(),(function fuck(){return \"Ik\";})(),(function" ascii
    $s3  = "eturn \"Za\";})(),(function fuck(){return \"IPu\";})(),(function fuck(){return \"DWe\";})(),(function fuck(){return \"Jo\";})()," ascii
    $s4  = "\"YAv\";})(),(function fuck(){return \"Np\";})(),(function fuck(){return \"IPu\";})(),(function fuck(){return \"MBg\";})(),(func" ascii
    $s5  = "tion fuck(){return \"Jg\";})(),(function fuck(){return \"Vb\";})(),(function fuck(){return \"MOj\";})(),(function fuck(){return " ascii
    $s6  = "on fuck(){return \"LGo\";})(),(function fuck(){return \"Cd\";})(),(function fuck(){return \"IPu\";})(),(function fuck(){return " ascii
    $s7  = "n fuck(){return \"XFd\";})(),(function fuck(){return \"YQt\";})(),(function fuck(){return \"AUx\";})(),(function fuck(){return " ascii
    $s8  = "fuck(){return \"IPu\";})(),(function fuck(){return \"Jo\";})(),(function fuck(){return \"MUs\";})(),(function fuck(){return \"Vb" ascii
    $s9  = "(){return \"DRx\";})(),(function fuck(){return \"Ai\";})(),(function fuck(){return \"Jh\";})(),(function fuck(){return \"IPu\";}" ascii
    $s10 = "tion fuck(){return \"MBg\";})(),(function fuck(){return \"IPu\";})(),(function fuck(){return \"Xw\";})(),(function fuck(){return" ascii
    $s11 = "{return \"Zy\";})(),(function fuck(){return \"GWo\";})(),(function fuck(){return \"DAa\";})(),(function fuck(){return \"Np\";})(" ascii
    $s12 = ")(),(function fuck(){return \"IPu\";})(),(function fuck(){return \"XHj\";})(),(function fuck(){return \"Zy\";})(),(function fuck" ascii
    $s13 = "(function fuck(){return \"Py\";})(),(function fuck(){return \"MOj\";})(),(function fuck(){return \"IPu\";})(),(function fuck(){r" ascii
    $s14 = "IPu\";})(),(function fuck(){return \"XFd\";})(),(function fuck(){return \"MUs\";})(),(function fuck(){return \"PDf\";})(),(funct" ascii
    $s15 = "ction fuck(){return \"DRx\";})(),(function fuck(){return \"IPu\";})(),(function fuck(){return \"XHj\";})(),(function fuck(){retu" ascii
    $s16 = "on fuck(){return \"QTc\";})(),(function fuck(){return \"DRx\";})(),(function fuck(){return \"XCr\";})(),(function fuck(){return " ascii
    $s17 = "\"DRx\";})(),(function fuck(){return \"Hs\";})(),(function fuck(){return \"Za\";})(),(function fuck(){return \"DRx\";})(),(funct" ascii
    $s18 = "fuck(){return \"IPu\";})(),(function fuck(){return \"Nm\";})(),(function fuck(){return \"Sx\";})(),(function fuck(){return \"Vb" ascii
    $s19 = "nction fuck(){return \"Za\";})(),(function fuck(){return \"IPu\";})(),(function fuck(){return \"We\";})(),(function fuck(){retur" ascii
    $s20 = "uck(){return \"DRx\";})(),(function fuck(){return \"IPu\";})(),(function fuck(){return \"Jo\";})(),(function fuck(){return \"ZVi" ascii

  condition:
    (uint16(0) == 0x2f0a and (8 of them)
    ) or (all of them)
}