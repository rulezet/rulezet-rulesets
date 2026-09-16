rule _20160921_033cb159a63153428b22d38108b692e4_20160921_220036ca1d41_670 {
  meta:
    description = "datamaliciousorder - from files 20160921_033cb159a63153428b22d38108b692e4.js, 20160921_220036ca1d4152e6bd72a833a4b3f832.js, 20160921_8b0f3892ae56f8c06d3baa62c262a12f.js, 20160921_b2c7637ff56cbf278f1a457ae1833df9.js, 20160921_bcf3911462135150c96c6b8eccf51628.js, 20160921_c459056d51b1a4ea3176139800021b35.js, 20160921_cbfbdc544b309301bc71d300d7726545.js, 20160921_d6dc24b88112bfdeca39a6062c7510f7.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "d370303fc83ddc3470e00cb54841641f9f338c2f025096e84d40782778041a8b"
    hash2       = "54f3e02c5b6d4d5d2db9a8d86252256d2f355ce582a09c9d870f84a9047c47ff"
    hash3       = "96514db18a22f5e5bde10feb1f6b426e5772d0f7e76f227e8d49a7a00bfb01b7"
    hash4       = "a19789bb6f28d27bc82c039f4db69fb5cc4c189a7a47cddfffcdc6eace37a408"
    hash5       = "b552c80ce6e203066590d8d065eb3336f999e3f3336ff06bb686520de3f326c5"
    hash6       = "2caf9c958877250774bdc190d1120c23a5fe115635a6c2d285aa8d62d171db39"
    hash7       = "135f44db2fcd47db2f5b9cd01f10f5c892ae119d904f5cb0ea4bbdaafba92963"
    hash8       = "b22daaadbd25f5bd920609cbc37e7ea10c4cd99c069220697c4c5db594cffee2"

  strings:
    $s1  = "nction f000(){return \"Tn\";})(),(function f000(){return \"GGn\";})(),(function f000(){return \"Sj\";})(),(function f000(){retur" ascii
    $s2  = "n \"Tn\";})(),(function f000(){return \"GGn\";})(),(function f000(){return \"MBb\";})(),(function f000(){return \"RLk\";})(),(fu" ascii
    $s3  = "n \"WIj\";})(),(function f000(){return \"GGn\";})(),(function f000(){return \"Br\";})(),(function f000(){return \"GGn\";})(),(fu" ascii
    $s4  = "nction f000(){return \"Tn\";})(),(function f000(){return \"GGn\";})(),(function f000(){return \"Yv\";})(),(function f000(){retur" ascii
    $s5  = ",(function f000(){return \"TKp\";})(),(function f000(){return \"TKl\";})(),(function f000(){return \"GGn\";})(),(function f000()" ascii
    $s6  = "{return \"Tn\";})(),(function f000(){return \"GGn\";})(),(function f000(){return \"MBb\";})(),(function f000(){return \"YTp\";})" ascii
    $s7  = "0(){return \"MBb\";})(),(function f000(){return \"Rh\";})(),(function f000(){return \"RPt\";})(),(function f000(){return \"GGn\"" ascii
    $s8  = "000(){return \"Mt\";})(),(function f000(){return \"Qz\";})(),(function f000(){return \"GGn\";})(),(function f000(){return \"WIj" ascii
    $s9  = "ion f000(){return \"EZu\";})(),(function f000(){return \"DNa\";})(),(function f000(){return \"Lo\";})(),(function f000(){return " ascii
    $s10 = "ion f000(){return \"GGn\";})(),(function f000(){return \"Yi\";})(),(function f000(){return \"Br\";})(),(function f000(){return " ascii
    $s11 = "(){return \"GGn\";})(),(function f000(){return \"SEo\";})(),(function f000(){return \"NYh\";})(),(function f000(){return \"GGn\"" ascii
    $s12 = "0(){return \"GGn\";})(),(function f000(){return \"IAa\";})(),(function f000(){return \"DAp\";})(),(function f000(){return \"Oe\"" ascii
    $s13 = ")(),(function f000(){return \"BMj\";})(),(function f000(){return \"Wb\";})(),(function f000(){return \"Yi\";})(),(function f000(" ascii
    $s14 = "ction f000(){return \"GGn\";})(),(function f000(){return \"Vj\";})(),(function f000(){return \"DAp\";})(),(function f000(){retur" ascii
    $s15 = "turn \"IPu\";})(),(function f000(){return \"Qa\";})(),(function f000(){return \"GGn\";})(),(function f000(){return \"WIj\";})()," ascii
    $s16 = "00(){return \"Tn\";})(),(function f000(){return \"GGn\";})(),(function f000(){return \"ZGq\";})(),(function f000(){return \"Oh\"" ascii
    $s17 = "urn \"RLk\";})(),(function f000(){return \"NYh\";})(),(function f000(){return \"GGn\";})(),(function f000(){return \"WIj\";})()," ascii
    $s18 = "})(),(function f000(){return \"DYs\";})(),(function f000(){return \"Sj\";})(),(function f000(){return \"DYx\";})(),(function f00" ascii
    $s19 = "tion f000(){return \"GGn\";})(),(function f000(){return \"Sj\";})(),(function f000(){return \"Lp\";})(),(function f000(){return " ascii
    $s20 = "rn \"Um\";})(),(function f000(){return \"DYx\";})(),(function f000(){return \"KXg\";})(),(function f000(){return \"GGn\";})(),(f" ascii

  condition:
    (uint16(0) == 0x2f0a and (8 of them)
    ) or (all of them)
}