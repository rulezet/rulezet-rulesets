rule _20160921_41f7b3abc606ff1ddad7593361eaa449_20160921_5d253f3fb318_1203 {
  meta:
    description = "datamaliciousorder - from files 20160921_41f7b3abc606ff1ddad7593361eaa449.js, 20160921_5d253f3fb31881c7c27141d74e02cacb.js, 20160921_d414cec9501c17802073a2f8f7b005c4.js, 20160921_e24d9e7aa16c031b748aba6965b02dcb.js, 20160921_e71c0801261b54c695ea1dac03e838bb.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "53e06a7234c6522ba26a61e46d13312e1063594b0e33bec9fae49d2dc4b77c28"
    hash2       = "ae85fe56260e8c9a1243da145f7594a08ac59bd50027af5e54b6d04e82f44e88"
    hash3       = "65e6cb34b6f46aaa1020cec9a648634a1eceb7e9d6ad0387fc939923e8236594"
    hash4       = "c005836c702d4e1615fb302fc6f799ca097db41daa5b8cf6a66e8874a454d65b"
    hash5       = "c36b557af1bcfc43e39bfaabcd74048c39fc37b5ac0e9561b161a6d3d2e54e76"

  strings:
    $s1  = " \"Ot\";})(),(function fuck(){return \"Xg\";})(),(function fuck(){return \"Py\";})(),(function fuck(){return \"IPu\";})(),(funct" ascii
    $s2  = "k(){return \"Ot\";})(),(function fuck(){return \"Qh\";})(),(function fuck(){return \"Xw\";})(),(function fuck(){return \"IPu\";}" ascii
    $s3  = "fuck(){return \"PDf\";})(),(function fuck(){return \"XHj\";})(),(function fuck(){return \"YAv\";})(),(function fuck(){return \"I" ascii
    $s4  = "k(){return \"IPu\";})(),(function fuck(){return \"Xw\";})(),(function fuck(){return \"GJx\";})(),(function fuck(){return \"ZLd\"" ascii
    $s5  = "rn \"IPu\";})(),(function fuck(){return \"Vf\";})(),(function fuck(){return \"EHo\";})(),(function fuck(){return \"Py\";})(),(fu" ascii
    $s6  = "function fuck(){return \"GWo\";})(),(function fuck(){return \"UOe\";})(),(function fuck(){return \"IPu\";})(),(function fuck(){r" ascii
    $s7  = "eturn \"IPu\";})(),(function fuck(){return \"Oh\";})(),(function fuck(){return \"Et\";})(),(function fuck(){return \"Jh\";})(),(" ascii
    $s8  = " fuck(){return \"IPu\";})(),(function fuck(){return \"Ot\";})(),(function fuck(){return \"Xg\";})(),(function fuck(){return \"IP" ascii
    $s9  = "Jx\";})(),(function fuck(){return \"DAa\";})(),(function fuck(){return \"Np\";})(),(function fuck(){return \"IPu\";})(),(functio" ascii
    $s10 = "turn \"MBg\";})(),(function fuck(){return \"IPu\";})(),(function fuck(){return \"Xw\";})(),(function fuck(){return \"ZLd\";})()," ascii
    $s11 = "(),(function fuck(){return \"IPu\";})(),(function fuck(){return \"Xw\";})(),(function fuck(){return \"Ai\";})(),(function fuck()" ascii
    $s12 = "ion fuck(){return \"MBg\";})(),(function fuck(){return \"IPu\";})(),(function fuck(){return \"Xw\";})(),(function fuck(){return " ascii
    $s13 = " \"PDf\";})(),(function fuck(){return \"We\";})(),(function fuck(){return \"Pc\";})(),(function fuck(){return \"Xw\";})(),(funct" ascii
    $s14 = "\"Cd\";})(),(function fuck(){return \"AUx\";})(),(function fuck(){return \"IPu\";})(),(function fuck(){return \"MBg\";})(),(func" ascii
    $s15 = "n \"To\";})(),(function fuck(){return \"Xw\";})(),(function fuck(){return \"IPu\";})(),(function fuck(){return \"DRx\";})(),(fun" ascii
    $s16 = "ion fuck(){return \"Za\";})(),(function fuck(){return \"IPu\";})(),(function fuck(){return \"XHj\";})(),(function fuck(){return " ascii

  condition:
    (uint16(0) == 0x2f0a and (8 of them)
    ) or (all of them)
}