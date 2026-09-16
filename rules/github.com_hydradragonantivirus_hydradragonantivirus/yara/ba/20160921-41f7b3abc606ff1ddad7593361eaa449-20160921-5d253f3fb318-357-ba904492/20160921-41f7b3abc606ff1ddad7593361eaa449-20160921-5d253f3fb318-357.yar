rule _20160921_41f7b3abc606ff1ddad7593361eaa449_20160921_5d253f3fb318_357 {
  meta:
    description = "datamaliciousorder - from files 20160921_41f7b3abc606ff1ddad7593361eaa449.js, 20160921_5d253f3fb31881c7c27141d74e02cacb.js, 20160921_5f040a1454cafc62100cb4449da0b7e2.js, 20160921_5fbbbcb8f403a68df153b90d52e5fff9.js, 20160921_d414cec9501c17802073a2f8f7b005c4.js, 20160921_e24d9e7aa16c031b748aba6965b02dcb.js, 20160921_e71c0801261b54c695ea1dac03e838bb.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "53e06a7234c6522ba26a61e46d13312e1063594b0e33bec9fae49d2dc4b77c28"
    hash2       = "ae85fe56260e8c9a1243da145f7594a08ac59bd50027af5e54b6d04e82f44e88"
    hash3       = "0ffb0f3f8e3e8ace2b8b6c1bccf53c8b5a11fd2ed00ff3b54971e8b0ca5e139d"
    hash4       = "1e2661f95b6bb745bac719b1313cfa9a489ecd857f66bfe9fe5398391e372ca4"
    hash5       = "65e6cb34b6f46aaa1020cec9a648634a1eceb7e9d6ad0387fc939923e8236594"
    hash6       = "c005836c702d4e1615fb302fc6f799ca097db41daa5b8cf6a66e8874a454d65b"
    hash7       = "c36b557af1bcfc43e39bfaabcd74048c39fc37b5ac0e9561b161a6d3d2e54e76"

  strings:
    $s1  = "(){return \"Dc\";})(),(function fuck(){return \"Py\";})(),(function fuck(){return \"IPu\";})(),(function fuck(){return \"MBg\";}" ascii
    $s2  = "k(){return \"IPu\";})(),(function fuck(){return \"XCr\";})(),(function fuck(){return \"Wo\";})(),(function fuck(){return \"Ik\";" ascii
    $s3  = "fuck(){return \"Za\";})(),(function fuck(){return \"IPu\";})(),(function fuck(){return \"Wo\";})(),(function fuck(){return \"MIl" ascii
    $s4  = "\"IPu\";})(),(function fuck(){return \"Xw\";})(),(function fuck(){return \"IOs\";})(),(function fuck(){return \"Mw\";})(),(funct" ascii
    $s5  = ")(),(function fuck(){return \"IPu\";})(),(function fuck(){return \"DWe\";})(),(function fuck(){return \"MIl\";})(),(function fuc" ascii
    $s6  = ")(),(function fuck(){return \"Qh\";})(),(function fuck(){return \"MUs\";})(),(function fuck(){return \"IPu\";})(),(function fuck" ascii
    $s7  = "return \"IPu\";})(),(function fuck(){return \"XCr\";})(),(function fuck(){return \"IOs\";})(),(function fuck(){return \"Py\";})(" ascii
    $s8  = ",(function fuck(){return \"IPu\";})(),(function fuck(){return \"Nm\";})(),(function fuck(){return \"Yk\";})(),(function fuck(){r" ascii
    $s9  = "n \"YQt\";})(),(function fuck(){return \"ZLd\";})(),(function fuck(){return \"Na\";})(),(function fuck(){return \"IPu\";})(),(fu" ascii
    $s10 = "n \"Wo0\";})(),(function fuck(){return \"EHo\";})(),(function fuck(){return \"Xw\";})(),(function fuck(){return \"IPu\";})(),(fu" ascii
    $s11 = " fuck(){return \"Xw\";})(),(function fuck(){return \"IOs\";})(),(function fuck(){return \"Xw\";})(),(function fuck(){return \"IP" ascii
    $s12 = "ction fuck(){return \"IPu\";})(),(function fuck(){return \"DWe\";})(),(function fuck(){return \"Ik\";})(),(function fuck(){retur" ascii
    $s13 = "g\";})(),(function fuck(){return \"Dc\";})(),(function fuck(){return \"YAv\";})(),(function fuck(){return \"Xg\";})(),(function " ascii
    $s14 = ")(),(function fuck(){return \"We\";})(),(function fuck(){return \"Ik\";})(),(function fuck(){return \"IPu\";})(),(function fuck(" ascii
    $s15 = "ck(){return \"Za\";})(),(function fuck(){return \"IPu\";})(),(function fuck(){return \"Yk\";})(),(function fuck(){return \"PDf\"" ascii
    $s16 = "turn \"IPu\";})(),(function fuck(){return \"Xw\";})(),(function fuck(){return \"GJx\";})(),(function fuck(){return \"ZWu\";})()," ascii
    $s17 = "\"Za\";})(),(function fuck(){return \"IPu\";})(),(function fuck(){return \"Qh\";})(),(function fuck(){return \"GJx\";})(),(funct" ascii
    $s18 = "uck(){return \"Za\";})(),(function fuck(){return \"IPu\";})(),(function fuck(){return \"XHj\";})(),(function fuck(){return \"Et" ascii
    $s19 = "return \"Ar\";})(),(function fuck(){return \"Fv\";})(),(function fuck(){return \"Xw\";})(),(function fuck(){return \"IPu\";})()," ascii
    $s20 = "Yk\";})(),(function fuck(){return \"Na\";})(),(function fuck(){return \"LGo\";})(),(function fuck(){return \"IPu\";})(),(functio" ascii

  condition:
    (uint16(0) == 0x2f0a and (8 of them)
    ) or (all of them)
}