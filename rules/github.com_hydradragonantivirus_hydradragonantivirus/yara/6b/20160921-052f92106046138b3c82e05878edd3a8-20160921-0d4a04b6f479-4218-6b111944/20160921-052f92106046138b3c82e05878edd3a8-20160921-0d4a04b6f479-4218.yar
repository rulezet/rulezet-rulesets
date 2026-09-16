rule _20160921_052f92106046138b3c82e05878edd3a8_20160921_0d4a04b6f479_4218 {
  meta:
    description = "datamaliciousorder - from files 20160921_052f92106046138b3c82e05878edd3a8.js, 20160921_0d4a04b6f4795f89c068cce75e132259.js, 20160921_11c4976357ef8a651d058575507518ca.js, 20160921_15779a074d56c3a097b4f7014a2c30f9.js, 20160921_1a47c8a8ea95b60eabaed27e984edacd.js, 20160921_214342143d6b7e971a1c8d2679379cb7.js, 20160921_2c5e8ccbd48636e7c625aae6ef954560.js, 20160921_37c1eae8c73482d7ccd62bb1c25f74b0.js, 20160921_44880573519212a90b7d910319fc31d8.js, 20160921_4cbbeff2b84f01cc3ab55f4eb29babb2.js, 20160921_4d30edc3a4e3226feee5b6289df9e399.js, 20160921_7dec24f022af3c1ffe46748172dd6cad.js, 20160921_814859e3f9dab39a18edf940d1dd5650.js, 20160921_93920c7f8d8dcef0135d270226e913f5.js, 20160921_b1a0d856c15e8cb36e6ba699332db942.js, 20160921_d35b8ea76f45dbc35f302f0ac5357655.js, 20160921_df51150cb4977f20502f85bfda11d939.js, 20160921_e26fc4dc1ccef911251bba0675c76ce0.js, 20160921_e6b8063519cd61bbba9375bf86215501.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "4812ea00b657b288e9ad51c72fcf466179e82a552fa3278fa9a896cc053c9fdc"
    hash2       = "e80f63f8ef5a9b52f119cc58d120fd7d74784d15d23ddc339948cb92383c800c"
    hash3       = "aee597813bd24d68729b505b5e718b120274cb1db588f64e61c1a4eb85f6bf11"
    hash4       = "aac4640bf20c6d05cb7c57f9703d60beee7ea9dfc98b851cabc5976b3d117b8d"
    hash5       = "b5a5f062c9d94508668ecb987b9d855fefbcdb1cf10f3efded37c21fc6893b0c"
    hash6       = "8dcc208c118a95c2f88df14e844ed832ee1e06bdf992329e8a721bd7aaa936e8"
    hash7       = "70244ca5fa124af09b1f94729567c09dbc52c05035ee7d20cbe87d35e1fe63c8"
    hash8       = "8e724c0f7c8722eec82dd0f37b13b38ab5c357aeccb2cc6c36efae80bae66a8a"
    hash9       = "8427ee610833efbf68884e3ec13c4357ae35e1aa0bf8ddc2ffe99b9a7f44fb40"
    hash10      = "698c46439ef391a98b04ac1a2759ff8a84b30a9c444a7575c5290eb0aa4b66b9"
    hash11      = "d28b5e72375443a9ef1a43fee185a0e5563672a0764eef4f58a90a27302162ea"
    hash12      = "402e919998fdba69cb3992879db4f947916245c38915db643643952fa450e947"
    hash13      = "c61c4f66b5cb5b5fa606db7d7b914cbb3fe4d8f1b8ae72ca6b16b707c575cfb0"
    hash14      = "a340a8acce75472b10972c1d41244236fbd98f0f2ecd9effbe64bc76604b8eb6"
    hash15      = "88dbe0c95aef9105f735a6441467700856e7377cc24ac1dbd7d9bcd256b0aa29"
    hash16      = "9dcc5774827243903cab74a4e9a77a6ec68f90a8c6ce60869e9bc7d13bcac921"
    hash17      = "81cf54f681cedb1b59ee2e355f226c046ac83c55ad32ce5241949279bb194bf1"
    hash18      = "f1074dcd9f3ae62af13634c9f88af0a235b2e315a2697fc222ce96bad51ca1a1"
    hash19      = "70ad2f9c8f844d4c80b1d4ce0f71f62f74e64671ae11d2d3af8e6ec764993403"

  strings:
    $s1 = "ck(){return \"USf\";})(),(function fuck(){return \"LGo\";})(),(function fuck(){return \"Pc\";})(),(function fuck(){return \"Xg\"" ascii
    $s2 = "unction fuck(){return \"Na\";})(),(function fuck(){return \"Xg\";})(),(function fuck(){return \"Xw\";})(),(function fuck(){retur" ascii
    $s3 = "unction fuck(){return \"FJs\";})(),(function fuck(){return \"YAv\";})(),(function fuck(){return \"Xw\";})(),(function fuck(){ret" ascii
    $s4 = "\"UXf\";})(),(function fuck(){return \"KVh\";})(),(function fuck(){return \"YAv\";})(),(function fuck(){return \"YAv\";})(),(fun" ascii
    $s5 = ",(function fuck(){return \"Wn\";})(),(function fuck(){return \"Za\";})(),(function fuck(){return \"EHo\";})(),(function fuck(){r" ascii

  condition:
    (uint16(0) == 0x2f0a and (all of them)
    ) or (all of them)
}