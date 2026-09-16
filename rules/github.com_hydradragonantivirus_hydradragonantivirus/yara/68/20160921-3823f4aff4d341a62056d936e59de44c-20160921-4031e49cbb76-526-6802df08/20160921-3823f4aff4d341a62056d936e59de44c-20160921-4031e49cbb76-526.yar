rule _20160921_3823f4aff4d341a62056d936e59de44c_20160921_4031e49cbb76_526 {
  meta:
    description = "datamaliciousorder - from files 20160921_3823f4aff4d341a62056d936e59de44c.js, 20160921_4031e49cbb76e44dd58fa572b63a00c7.js, 20160921_4809ff2679793c2b9af03e18ec3702ef.js, 20160921_4f8422c91e79e3073e201b0b279b1fbb.js, 20160921_510713862e5c8c05841e5272407127f3.js, 20160921_531eaafa1b0a00d86f2203fbd289dd63.js, 20160921_5ed9729c3ab2cb9d37d8a088af1aba59.js, 20160921_73e0cbee151147d27e01ecc015f640b4.js, 20160921_7e15ac2755366d4644a83de8ec9c1a47.js, 20160921_91424e3b4f105c156aa0fa6f22c2306f.js, 20160921_c979e38640433b8c93e1c145417c85cb.js, 20160921_fa8c93ef210d8b4c6831cb1425f1dc9b.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "d0b475c02138425371c1df69faa8ac5c3d739764950c4a65034372b4455ac04d"
    hash2       = "42519dff3fd2ed2dc9bcd0f12a16fe310be93f90efd5d40110f336dc5010d050"
    hash3       = "2c2d464143196a0237396460d274213cf5b3de772f4205aee0525b67ca1bfd6c"
    hash4       = "f1cc54af4d213d0cd37c81b29d25c29bf00892e3458ef2e236563c69fd58b94a"
    hash5       = "9f9cd81d24cdba49fd83fed4aa0c3ce028729b44e223720bae200336b5992e5e"
    hash6       = "d28500022264ce61d9d988db6f8ddee46acc7dea6f898510f532ee48f87a0c93"
    hash7       = "c5908838424a9cae8eb5587cff7048056b427db1deb512dcbe9ca852a402e03d"
    hash8       = "0ad4b632b07e5e4526b874097c116e5183b155ec4b9cf40e3f13ece0ce027344"
    hash9       = "97eaf7c50f22bfc94f97a02e5e83a8f1fb3583717fb9f4a6666ae882ea4d6f55"
    hash10      = "b4a035e38404ad09be99953980865cdbcda5dd05b664dff96722afb53b0c9e29"
    hash11      = "62a468202853ba6a8adb456e8c12b66f8794360c094a85e6d4d2cf43d13a75ce"
    hash12      = "7e7bb1d2ade80c23d5462f8e4a470a3c3245b07b8a709a3c911ff76a8c32da35"

  strings:
    $s1  = ",(function fuck(){return \"IOs\";})(),(function fuck(){return \"Pc\";})(),(function fuck(){return \"Xw\";})(),(function fuck(){r" ascii
    $s2  = "ck(){return \"Xg\";})(),(function fuck(){return \"Sx\";})(),(function fuck(){return \"To\";})(),(function fuck(){return \"Mw\";}" ascii
    $s3  = "nction fuck(){return \"XFd\";})(),(function fuck(){return \"To\";})(),(function fuck(){return \"Xw\";})(),(function fuck(){retur" ascii
    $s4  = "ck(){return \"IPu\";})(),(function fuck(){return \"Qh\";})(),(function fuck(){return \"DWe\";})(),(function fuck(){return \"AUx" ascii
    $s5  = "uck(){return \"Za\";})(),(function fuck(){return \"IPu\";})(),(function fuck(){return \"Ug\";})(),(function fuck(){return \"Cd\"" ascii
    $s6  = "h\";})(),(function fuck(){return \"USf\";})(),(function fuck(){return \"IPu\";})(),(function fuck(){return \"MBg\";})(),(functio" ascii
    $s7  = "(),(function fuck(){return \"Zy\";})(),(function fuck(){return \"Qh\";})(),(function fuck(){return \"Ik\";})(),(function fuck(){" ascii
    $s8  = "eturn \"MBg\";})(),(function fuck(){return \"IPu\";})(),(function fuck(){return \"Xw\";})(),(function fuck(){return \"XFd\";})()" ascii
    $s9  = "fuck(){return \"CCb\";})(),(function fuck(){return \"To\";})(),(function fuck(){return \"Xw\";})(),(function fuck(){return \"IPu" ascii
    $s10 = "tion fuck(){return \"Pc\";})(),(function fuck(){return \"Xg\";})(),(function fuck(){return \"Na\";})(),(function fuck(){return " ascii
    $s11 = "ction fuck(){return \"Mw\";})(),(function fuck(){return \"Fv\";})(),(function fuck(){return \"LLv\";})(),(function fuck(){return" ascii
    $s12 = "unction fuck(){return \"Fv\";})(),(function fuck(){return \"ADy\";})(),(function fuck(){return \"IPu\";})(),(function fuck(){ret" ascii
    $s13 = "{return \"Xw\";})(),(function fuck(){return \"To\";})(),(function fuck(){return \"GJx\";})(),(function fuck(){return \"Ot\";})()" ascii
    $s14 = "a\";})(),(function fuck(){return \"IPu\";})(),(function fuck(){return \"Et\";})(),(function fuck(){return \"CCb\";})(),(function" ascii
    $s15 = "We\";})(),(function fuck(){return \"Et\";})(),(function fuck(){return \"Za\";})(),(function fuck(){return \"IPu\";})(),(function" ascii
    $s16 = "\"Xw\";})(),(function fuck(){return \"Oh\";})(),(function fuck(){return \"Dc\";})(),(function fuck(){return \"Xw\";})(),(functio" ascii
    $s17 = "ion fuck(){return \"Av\";})(),(function fuck(){return \"Xw\";})(),(function fuck(){return \"IPu\";})(),(function fuck(){return " ascii
    $s18 = "{return \"ZLd\";})(),(function fuck(){return \"ZLd\";})(),(function fuck(){return \"Xw\";})(),(function fuck(){return \"IPu\";})" ascii
    $s19 = "n \"Vf\";})(),(function fuck(){return \"Yk\";})(),(function fuck(){return \"Xw\";})(),(function fuck(){return \"IPu\";})(),(func" ascii
    $s20 = "){return \"Xw\";})(),(function fuck(){return \"Fv\";})(),(function fuck(){return \"Xg\";})(),(function fuck(){return \"XCr\";})(" ascii

  condition:
    (uint16(0) == 0x2f0a and (8 of them)
    ) or (all of them)
}