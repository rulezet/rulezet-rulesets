rule _20160921_9dad243650b7872772e7037b467b5a2e_20160921_da68ef3a64fe_1054 {
  meta:
    description = "datamaliciousorder - from files 20160921_9dad243650b7872772e7037b467b5a2e.js, 20160921_da68ef3a64fe9761a5f4505bcaef8f82.js, 20160922_edfdc00dbdbb7dfd43478925b51e4a4b.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "0d6dd5e22f8f66e5240683d3b57744793a88315a385138ff11409b0c03a9c448"
    hash2       = "cecd93896e2d90bed54f31f9e387b5dcec7c277d5e455e561112b07c63d26ed5"
    hash3       = "8672bbf21d7f10931a3f6328634b8b4e6160470a85d97fb93d56cb5eedb10599"

  strings:
    $s1  = "(){return \"Tn\";})(),(function f000(){return \"GGn\";})(),(function f000(){return \"RLk\";})(),(function f000(){return \"Yv\";}" ascii
    $s2  = "on f000(){return \"GGn\";})(),(function f000(){return \"Lp\";})(),(function f000(){return \"Lp\";})(),(function f000(){return \"" ascii
    $s3  = "})(),(function f000(){return \"MOc\";})(),(function f000(){return \"Br\";})(),(function f000(){return \"GGn\";})(),(function f00" ascii
    $s4  = "return \"Tb\";})(),(function f000(){return \"BQb\";})(),(function f000(){return \"TKl\";})(),(function f000(){return \"GGn\";})(" ascii
    $s5  = "ction f000(){return \"Yz\";})(),(function f000(){return \"Yi\";})(),(function f000(){return \"GGn\";})(),(function f000(){return" ascii
    $s6  = "),(function f000(){return \"Vj\";})(),(function f000(){return \"DAp\";})(),(function f000(){return \"DYs\";})(),(function f000()" ascii
    $s7  = "ion f000(){return \"WIj\";})(),(function f000(){return \"GGn\";})(),(function f000(){return \"Br\";})(),(function f000(){return " ascii
    $s8  = "Eg\";})(),(function f000(){return \"Wy\";})(),(function f000(){return \"Oe\";})(),(function f000(){return \"Br\";})(),(function " ascii
    $s9  = " \"Tn\";})(),(function f000(){return \"GGn\";})(),(function f000(){return \"KDh\";})(),(function f000(){return \"Tb\";})(),(func" ascii
    $s10 = "n \"GGn\";})(),(function f000(){return \"Go\";})(),(function f000(){return \"IPu\";})(),(function f000(){return \"GGn\";})(),(fu" ascii
    $s11 = "unction f000(){return \"TKp\";})(),(function f000(){return \"Do\";})(),(function f000(){return \"GGn\";})(),(function f000(){ret" ascii
    $s12 = ",(function f000(){return \"GGn\";})(),(function f000(){return \"Yv\";})(),(function f000(){return \"DNa\";})(),(function f000(){" ascii
    $s13 = "0(){return \"ZIi\";})(),(function f000(){return \"GGn\";})(),(function f000(){return \"WIj\";})(),(function f000(){return \"GGn" ascii
    $s14 = "n \"Sv\";})(),(function f000(){return \"Br\";})(),(function f000(){return \"GGn\";})(),(function f000(){return \"MDb\";})(),(fun" ascii
    $s15 = "ction f000(){return \"MBb\";})(),(function f000(){return \"MBb\";})(),(function f000(){return \"Um\";})(),(function f000(){retur" ascii
    $s16 = "000(){return \"Br\";})(),(function f000(){return \"Um\";})(),(function f000(){return \"DYs\";})(),(function f000(){return \"Br\"" ascii
    $s17 = "function f000(){return \"Br\";})(),(function f000(){return \"MBb\";})(),(function f000(){return \"Mt\";})(),(function f000(){ret" ascii
    $s18 = "\"Nv\";})(),(function f000(){return \"UEg\";})(),(function f000(){return \"Do\";})(),(function f000(){return \"GGn\";})(),(funct" ascii

  condition:
    (uint16(0) == 0x2f0a and (8 of them)
    ) or (all of them)
}