rule _20160921_1766f5c818d6371cb36488c98158ccd2_20160921_202394e6610d_725 {
  meta:
    description = "datamaliciousorder - from files 20160921_1766f5c818d6371cb36488c98158ccd2.js, 20160921_202394e6610dfa0f27f737c781d5c579.js, 20160921_66de660457cd1dcbe458e50b91bafaca.js, 20160921_8d22ed47876b303a1415a88483556238.js, 20160921_99369f59b90fb2df18b8570f0403febc.js, 20160921_ccabe4fce99c1ebb627aa374a501f33c.js, 20160921_cebdb99ce2e54d24acef5b8ee0096562.js, 20160921_e6569e3fc498e9fab243cf8dcef2ac51.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "4d8985b767534ef1312401b6a38570477e0c87ed4ef37c945eee55179929c0a4"
    hash2       = "d10df61dcb3a781b5266597c0f1a9d52066cebbebf5196ad93fd81855575ed11"
    hash3       = "0c92eafe23596e161cf04cc6206b7e5cac5dafb3ce36772cc5a8a4f0f827211c"
    hash4       = "666a3f8cd9a533a20e260aad6bcb18265aad030f6f978c4cc3c9da557262f1ae"
    hash5       = "224e0a3dfee910c8afb81d7298f89c0b6e937cbd8062c03cedbe500c3dfe98a2"
    hash6       = "449fe576ee25f77acba5442d771e770819941d7dbf354b5123ca5211ef743189"
    hash7       = "87071d18d308dc7717dabe03dc0d11efe7ee7231e95d9fca71e480f5f2430f7d"
    hash8       = "d08c501a52afbdcde7669d2b9c40865025e38aa75b2aebf8c71433565dbc7010"

  strings:
    $s1  = "Tn\";})(),(function f000(){return \"GGn\";})(),(function f000(){return \"IAa\";})(),(function f000(){return \"PTi\";})(),(functi" ascii
    $s2  = "unction f000(){return \"DNa\";})(),(function f000(){return \"YTp\";})(),(function f000(){return \"XTn\";})(),(function f000(){re" ascii
    $s3  = "{return \"Tn\";})(),(function f000(){return \"GGn\";})(),(function f000(){return \"PTs\";})(),(function f000(){return \"RLk\";})" ascii
    $s4  = "urn \"YTp\";})(),(function f000(){return \"BQb\";})(),(function f000(){return \"BQb\";})(),(function f000(){return \"Yi\";})(),(" ascii
    $s5  = "(){return \"Yz\";})(),(function f000(){return \"MJq\";})(),(function f000(){return \"YTp\";})(),(function f000(){return \"Br\";}" ascii
    $s6  = "on f000(){return \"TKl\";})(),(function f000(){return \"Lp\";})(),(function f000(){return \"KIc\";})(),(function f000(){return " ascii
    $s7  = "0(){return \"Oe\";})(),(function f000(){return \"MJq\";})(),(function f000(){return \"DAp\";})(),(function f000(){return \"DYx\"" ascii
    $s8  = "{return \"UEg\";})(),(function f000(){return \"Uo\";})(),(function f000(){return \"Um\";})(),(function f000(){return \"Uo\";})()" ascii
    $s9  = " f000(){return \"ZGq\";})(),(function f000(){return \"Wy\";})(),(function f000(){return \"GGn\";})(),(function f000(){return \"W" ascii
    $s10 = ")(),(function f000(){return \"Tn\";})(),(function f000(){return \"SGs\";})(),(function f000(){return \"TKp\";})(),(function f000" ascii
    $s11 = "000(){return \"DAp\";})(),(function f000(){return \"Nv\";})(),(function f000(){return \"Br\";})(),(function f000(){return \"GGn" ascii
    $s12 = ",(function f000(){return \"GGn\";})(),(function f000(){return \"Tb\";})(),(function f000(){return \"Vu\";})(),(function f000(){r" ascii
    $s13 = "){return \"GGn\";})(),(function f000(){return \"RLk\";})(),(function f000(){return \"Nv\";})(),(function f000(){return \"TKp\";}" ascii
    $s14 = "eturn \"GGn\";})(),(function f000(){return \"HJm\";})(),(function f000(){return \"Qa\";})(),(function f000(){return \"Tn\";})()," ascii
    $s15 = "Sj\";})(),(function f000(){return \"IPu\";})(),(function f000(){return \"GGn\";})(),(function f000(){return \"WIj\";})(),(functi" ascii
    $s16 = "tion f000(){return \"TKp\";})(),(function f000(){return \"RPt\";})(),(function f000(){return \"GGn\";})(),(function f000(){retur" ascii
    $s17 = "n \"GGn\";})(),(function f000(){return \"Br\";})(),(function f000(){return \"HJm\";})(),(function f000(){return \"PTi\";})(),(fu" ascii
    $s18 = "00(){return \"Br\";})(),(function f000(){return \"Wy\";})(),(function f000(){return \"Oe\";})(),(function f000(){return \"Br\";}" ascii
    $s19 = " f000(){return \"KXg\";})(),(function f000(){return \"Ml\";})(),(function f000(){return \"Oe\";})(),(function f000(){return \"NB" ascii
    $s20 = " f000(){return \"GGn\";})(),(function f000(){return \"MBb\";})(),(function f000(){return \"Sv\";})(),(function f000(){return \"R" ascii

  condition:
    (uint16(0) == 0x2f0a and (8 of them)
    ) or (all of them)
}