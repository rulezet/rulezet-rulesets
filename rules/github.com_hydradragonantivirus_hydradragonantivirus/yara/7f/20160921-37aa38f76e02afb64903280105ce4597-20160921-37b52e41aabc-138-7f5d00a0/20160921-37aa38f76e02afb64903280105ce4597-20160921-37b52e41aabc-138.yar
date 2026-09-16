rule _20160921_37aa38f76e02afb64903280105ce4597_20160921_37b52e41aabc_138 {
  meta:
    description = "datamaliciousorder - from files 20160921_37aa38f76e02afb64903280105ce4597.js, 20160921_37b52e41aabc93218d864c1665a33610.js, 20160921_6d18600f3019656b0ab414a3d1a69ddb.js, 20160921_7f829eb25609c6f6d37ef18f9c4f8ad7.js, 20160921_b7400937fc4eb76c7ea3adaa321d7619.js, 20160921_c1ad71fea9bd3e371590c0c373f087a1.js, 20160921_dd666c66b3f13d3a71b957c0e646c0a0.js, 20160921_eba3e9dc8ad614a7e5c422a93cd7b424.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "768a32c669c193375bb8e7adb97cdbb697cd6f4f09fb5dc67bb63e62b7de29cf"
    hash2       = "c506490b3737e1b21522717204e4143ada427e9af58fe86e42ed31dfd0fde66a"
    hash3       = "fb0471dc4828588d37d01ddaa7b9454e82acacc4dfdd9f0998b461661e3810db"
    hash4       = "cbb0232bbf0751233c3e647bef431987aa4666e8c60b9ff699f55e31318c3e22"
    hash5       = "91a8cd111f3381e8f00611988dc7860cfb507d4d297884f9d7d7a01ae96c0fca"
    hash6       = "cf0e0decfb5414f48e1bcf494a6c63e6249e9ac1433d4fba6a461b5970957194"
    hash7       = "77e753e21a464bef9fad04f7d41ce8b192c797808ff1b22efe474c612c25f2b2"
    hash8       = "f0f6c6f4fe3daf7aae3b8d7276adbcc6577a8bf844eeae945023523b63b6cc9a"

  strings:
    $s1  = "unction f000(){return \"Wy\";})(),(function f000(){return \"Tn\";})(),(function f000(){return \"Oe\";})(),(function f000(){retur" ascii
    $s2  = " f000(){return \"Lp\";})(),(function f000(){return \"MJq\";})(),(function f000(){return \"GGn\";})(),(function f000(){return \"W" ascii
    $s3  = "){return \"Tn\";})(),(function f000(){return \"GGn\";})(),(function f000(){return \"RLk\";})(),(function f000(){return \"MJq\";}" ascii
    $s4  = "f000(){return \"Iq\";})(),(function f000(){return \"GGn\";})(),(function f000(){return \"WIj\";})(),(function f000(){return \"GG" ascii
    $s5  = "turn \"Go\";})(),(function f000(){return \"Sj\";})(),(function f000(){return \"Sv\";})(),(function f000(){return \"HJm\";})(),(f" ascii
    $s6  = "00(){return \"GGn\";})(),(function f000(){return \"RLk\";})(),(function f000(){return \"Uo\";})(),(function f000(){return \"Qj\"" ascii
    $s7  = "c\";})(),(function f000(){return \"UEg\";})(),(function f000(){return \"Mt\";})(),(function f000(){return \"UEg\";})(),(function" ascii
    $s8  = "unction f000(){return \"Wy\";})(),(function f000(){return \"Fs\";})(),(function f000(){return \"KIc\";})(),(function f000(){retu" ascii
    $s9  = "(){return \"UEg\";})(),(function f000(){return \"Kw\";})(),(function f000(){return \"GGn\";})(),(function f000(){return \"WIj\";" ascii
    $s10 = "Ys\";})(),(function f000(){return \"DYx\";})(),(function f000(){return \"GGn\";})(),(function f000(){return \"WIj\";})(),(functi" ascii
    $s11 = "n f000(){return \"GGn\";})(),(function f000(){return \"ZFe\";})(),(function f000(){return \"MBb\";})(),(function f000(){return " ascii
    $s12 = "function f000(){return \"Iq\";})(),(function f000(){return \"TKp\";})(),(function f000(){return \"Sv\";})(),(function f000(){ret" ascii
    $s13 = "ction f000(){return \"GGn\";})(),(function f000(){return \"Br\";})(),(function f000(){return \"Go\";})(),(function f000(){return" ascii
    $s14 = "){return \"GGn\";})(),(function f000(){return \"Go\";})(),(function f000(){return \"DAp\";})(),(function f000(){return \"Yz\";})" ascii
    $s15 = "(){return \"MJq\";})(),(function f000(){return \"DAp\";})(),(function f000(){return \"DYx\";})(),(function f000(){return \"DYx\"" ascii
    $s16 = "(),(function f000(){return \"Rh\";})(),(function f000(){return \"BQb\";})(),(function f000(){return \"Br\";})(),(function f000()" ascii
    $s17 = "rn \"GGn\";})(),(function f000(){return \"DNa\";})(),(function f000(){return \"Rh\";})(),(function f000(){return \"GGn\";})(),(f" ascii
    $s18 = "nction f000(){return \"GGn\";})(),(function f000(){return \"Uo\";})(),(function f000(){return \"Sv\";})(),(function f000(){retur" ascii
    $s19 = "eturn \"Tn\";})(),(function f000(){return \"GGn\";})(),(function f000(){return \"PTs\";})(),(function f000(){return \"ZIi\";})()" ascii
    $s20 = "(){return \"GGn\";})(),(function f000(){return \"Br\";})(),(function f000(){return \"Go\";})(),(function f000(){return \"MBb\";}" ascii

  condition:
    (uint16(0) == 0x2f0a and (8 of them)
    ) or (all of them)
}