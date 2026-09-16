rule _20160921_03b650867a3952f7709688e58e8232f3_20160921_11c4976357ef_1321 {
  meta:
    description = "datamaliciousorder - from files 20160921_03b650867a3952f7709688e58e8232f3.js, 20160921_11c4976357ef8a651d058575507518ca.js, 20160921_15779a074d56c3a097b4f7014a2c30f9.js, 20160921_1a47c8a8ea95b60eabaed27e984edacd.js, 20160921_214342143d6b7e971a1c8d2679379cb7.js, 20160921_37c1eae8c73482d7ccd62bb1c25f74b0.js, 20160921_44880573519212a90b7d910319fc31d8.js, 20160921_4cbbeff2b84f01cc3ab55f4eb29babb2.js, 20160921_7dec24f022af3c1ffe46748172dd6cad.js, 20160921_93920c7f8d8dcef0135d270226e913f5.js, 20160921_b1a0d856c15e8cb36e6ba699332db942.js, 20160921_d35b8ea76f45dbc35f302f0ac5357655.js, 20160921_df51150cb4977f20502f85bfda11d939.js, 20160921_e6b8063519cd61bbba9375bf86215501.js, 20160921_ec2d2710e9217c2f295a4b410a623d5d.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "a775853212fe6663d7c077a64c0d4c851d4b7f261a6c0846b4552b556e12a5fe"
    hash2       = "aee597813bd24d68729b505b5e718b120274cb1db588f64e61c1a4eb85f6bf11"
    hash3       = "aac4640bf20c6d05cb7c57f9703d60beee7ea9dfc98b851cabc5976b3d117b8d"
    hash4       = "b5a5f062c9d94508668ecb987b9d855fefbcdb1cf10f3efded37c21fc6893b0c"
    hash5       = "8dcc208c118a95c2f88df14e844ed832ee1e06bdf992329e8a721bd7aaa936e8"
    hash6       = "8e724c0f7c8722eec82dd0f37b13b38ab5c357aeccb2cc6c36efae80bae66a8a"
    hash7       = "8427ee610833efbf68884e3ec13c4357ae35e1aa0bf8ddc2ffe99b9a7f44fb40"
    hash8       = "698c46439ef391a98b04ac1a2759ff8a84b30a9c444a7575c5290eb0aa4b66b9"
    hash9       = "402e919998fdba69cb3992879db4f947916245c38915db643643952fa450e947"
    hash10      = "a340a8acce75472b10972c1d41244236fbd98f0f2ecd9effbe64bc76604b8eb6"
    hash11      = "88dbe0c95aef9105f735a6441467700856e7377cc24ac1dbd7d9bcd256b0aa29"
    hash12      = "9dcc5774827243903cab74a4e9a77a6ec68f90a8c6ce60869e9bc7d13bcac921"
    hash13      = "81cf54f681cedb1b59ee2e355f226c046ac83c55ad32ce5241949279bb194bf1"
    hash14      = "70ad2f9c8f844d4c80b1d4ce0f71f62f74e64671ae11d2d3af8e6ec764993403"
    hash15      = "efabdabbb3a7d8e1d713826868acadadd9ab03b4cb57f3799d6add11f212fdd9"

  strings:
    $s1  = "k(){return \"Xw\";})(),(function fuck(){return \"UXf\";})(),(function fuck(){return \"DAa\";})(),(function fuck(){return \"Fv\";" ascii
    $s2  = "function fuck(){return \"Wo\";})(),(function fuck(){return \"XCr\";})(),(function fuck(){return \"EHo\";})(),(function fuck(){re" ascii
    $s3  = "(),(function fuck(){return \"Vf\";})(),(function fuck(){return \"EHo\";})(),(function fuck(){return \"IPu\";})(),(function fuck(" ascii
    $s4  = "nction fuck(){return \"DWe\";})(),(function fuck(){return \"Fv\";})(),(function fuck(){return \"IPu\";})(),(function fuck(){retu" ascii
    $s5  = "on fuck(){return \"Za\";})(),(function fuck(){return \"GJx\";})(),(function fuck(){return \"Xw\";})(),(function fuck(){return \"" ascii
    $s6  = " fuck(){return \"Za\";})(),(function fuck(){return \"UOe\";})(),(function fuck(){return \"IPu\";})(),(function fuck(){return \"M" ascii
    $s7  = "u\";})(),(function fuck(){return \"Oh\";})(),(function fuck(){return \"Sx\";})(),(function fuck(){return \"Jo\";})(),(function f" ascii
    $s8  = "eturn \"Et\";})(),(function fuck(){return \"Et\";})(),(function fuck(){return \"Xg\";})(),(function fuck(){return \"IPu\";})(),(" ascii
    $s9  = "ion fuck(){return \"ZLd\";})(),(function fuck(){return \"KVh\";})(),(function fuck(){return \"Np\";})(),(function fuck(){return " ascii
    $s10 = "unction fuck(){return \"XCr\";})(),(function fuck(){return \"GJx\";})(),(function fuck(){return \"ZVi\";})(),(function fuck(){re" ascii
    $s11 = ",(function fuck(){return \"KVh\";})(),(function fuck(){return \"ZLd\";})(),(function fuck(){return \"Xw\";})(),(function fuck(){" ascii
    $s12 = "return \"Xw\";})(),(function fuck(){return \"FJs\";})(),(function fuck(){return \"QTc\";})(),(function fuck(){return \"Ik\";})()" ascii
    $s13 = "ck(){return \"Xw\";})(),(function fuck(){return \"QTc\";})(),(function fuck(){return \"Xw\";})(),(function fuck(){return \"IPu\"" ascii
    $s14 = "on fuck(){return \"To\";})(),(function fuck(){return \"Xg\";})(),(function fuck(){return \"Xw\";})(),(function fuck(){return \"I" ascii
    $s15 = "tion fuck(){return \"Ve\";})(),(function fuck(){return \"YAv\";})(),(function fuck(){return \"RAi\";})(),(function fuck(){return" ascii

  condition:
    (uint16(0) == 0x2f0a and (8 of them)
    ) or (all of them)
}