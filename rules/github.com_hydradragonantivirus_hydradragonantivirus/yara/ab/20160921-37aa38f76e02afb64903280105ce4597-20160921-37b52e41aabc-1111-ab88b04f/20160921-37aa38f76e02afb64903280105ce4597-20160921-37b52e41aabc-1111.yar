rule _20160921_37aa38f76e02afb64903280105ce4597_20160921_37b52e41aabc_1111 {
  meta:
    description = "datamaliciousorder - from files 20160921_37aa38f76e02afb64903280105ce4597.js, 20160921_37b52e41aabc93218d864c1665a33610.js, 20160921_3a89132c20887c3360a3708984b884fb.js, 20160921_6d18600f3019656b0ab414a3d1a69ddb.js, 20160921_7f829eb25609c6f6d37ef18f9c4f8ad7.js, 20160921_ad69715850fae108d9a16055efb4f51c.js, 20160921_b7400937fc4eb76c7ea3adaa321d7619.js, 20160921_c1ad71fea9bd3e371590c0c373f087a1.js, 20160921_dd666c66b3f13d3a71b957c0e646c0a0.js, 20160921_eba3e9dc8ad614a7e5c422a93cd7b424.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "768a32c669c193375bb8e7adb97cdbb697cd6f4f09fb5dc67bb63e62b7de29cf"
    hash2       = "c506490b3737e1b21522717204e4143ada427e9af58fe86e42ed31dfd0fde66a"
    hash3       = "9687ad9b2ded14e00c5b17393de82acd451266863fb217fc6647e1add112f2fd"
    hash4       = "fb0471dc4828588d37d01ddaa7b9454e82acacc4dfdd9f0998b461661e3810db"
    hash5       = "cbb0232bbf0751233c3e647bef431987aa4666e8c60b9ff699f55e31318c3e22"
    hash6       = "76ed8c5c3ace4ce119f1561d5d61ca2e454da79e9156a8397e72d6eed3a22d74"
    hash7       = "91a8cd111f3381e8f00611988dc7860cfb507d4d297884f9d7d7a01ae96c0fca"
    hash8       = "cf0e0decfb5414f48e1bcf494a6c63e6249e9ac1433d4fba6a461b5970957194"
    hash9       = "77e753e21a464bef9fad04f7d41ce8b192c797808ff1b22efe474c612c25f2b2"
    hash10      = "f0f6c6f4fe3daf7aae3b8d7276adbcc6577a8bf844eeae945023523b63b6cc9a"

  strings:
    $s1  = "tion f000(){return \"GGn\";})(),(function f000(){return \"DAp\";})(),(function f000(){return \"Nv\";})(),(function f000(){return" ascii
    $s2  = "function f000(){return \"GGn\";})(),(function f000(){return \"IAa\";})(),(function f000(){return \"BQb\";})(),(function f000(){r" ascii
    $s3  = "return \"SEo\";})(),(function f000(){return \"Wy\";})(),(function f000(){return \"Br\";})(),(function f000(){return \"GGn\";})()" ascii
    $s4  = "){return \"Yv\";})(),(function f000(){return \"MJq\";})(),(function f000(){return \"GGn\";})(),(function f000(){return \"WIj\";}" ascii
    $s5  = "return \"Br\";})(),(function f000(){return \"DYs\";})(),(function f000(){return \"Tn\";})(),(function f000(){return \"Oe\";})()," ascii
    $s6  = " f000(){return \"HJm\";})(),(function f000(){return \"TKp\";})(),(function f000(){return \"Qz\";})(),(function f000(){return \"G" ascii
    $s7  = "s\";})(),(function f000(){return \"DYx\";})(),(function f000(){return \"YTp\";})(),(function f000(){return \"Br\";})(),(function" ascii
    $s8  = "tion f000(){return \"PTi\";})(),(function f000(){return \"DNa\";})(),(function f000(){return \"NYh\";})(),(function f000(){retur" ascii
    $s9  = "eturn \"Qa\";})(),(function f000(){return \"Wy\";})(),(function f000(){return \"GGn\";})(),(function f000(){return \"WIj\";})()," ascii
    $s10 = "function f000(){return \"Rh\";})(),(function f000(){return \"Km\";})(),(function f000(){return \"Yz\";})(),(function f000(){retu" ascii
    $s11 = "n \"GGn\";})(),(function f000(){return \"SEo\";})(),(function f000(){return \"Tn\";})(),(function f000(){return \"Kw\";})(),(fun" ascii
    $s12 = "0(){return \"ZFe\";})(),(function f000(){return \"Um\";})(),(function f000(){return \"Qj\";})(),(function f000(){return \"GGn\";" ascii
    $s13 = "eturn \"GGn\";})(),(function f000(){return \"Br\";})(),(function f000(){return \"Oe\";})(),(function f000(){return \"Um\";})(),(" ascii
    $s14 = "n f000(){return \"GGn\";})(),(function f000(){return \"Br\";})(),(function f000(){return \"Rh\";})(),(function f000(){return \"W" ascii
    $s15 = "0(){return \"Tn\";})(),(function f000(){return \"GGn\";})(),(function f000(){return \"ZGq\";})(),(function f000(){return \"DNa\"" ascii

  condition:
    (uint16(0) == 0x2f0a and (8 of them)
    ) or (all of them)
}