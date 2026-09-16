rule _20160921_27fb26e7e153703634890a2f9e37ef7b_20160921_cff7808833d9_74 {
  meta:
    description = "datamaliciousorder - from files 20160921_27fb26e7e153703634890a2f9e37ef7b.js, 20160921_cff7808833d9e819d4a4f10450848a81.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "867c0b561ad28bc562227169c7a21fbf367232ec2d2454d4bd819e1a42cc1b62"
    hash2       = "542990d73514ef4ff7fb1540013f789833830036dc9c9c2ad8c49c1bdabb1f2a"

  strings:
    $s1  = "eturn \"ZGq\";})(),(function f000(){return \"KXg\";})(),(function f000(){return \"TKl\";})(),(function f000(){return \"Qj\";})()" ascii
    $s2  = "\"OUx\";})(),(function f000(){return \"Qj\";})(),(function f000(){return \"Kw\";})(),(function f000(){return \"ZGq\";})(),(funct" ascii
    $s3  = "){return \"SGs\";})(),(function f000(){return \"RPt\";})(),(function f000(){return \"TRc\";})(),(function f000(){return \"QDg\";" ascii
    $s4  = "eturn \"Lp\";})(),(function f000(){return \"ZGq\";})(),(function f000(){return \"XTn\";})(),(function f000(){return \"GGn\";})()" ascii
    $s5  = "unction f000(){return \"EZu\";})(),(function f000(){return \"Br\";})(),(function f000(){return \"GGn\";})(),(function f000(){ret" ascii
    $s6  = "f000(){return \"KXg\";})(),(function f000(){return \"ZGq\";})(),(function f000(){return \"Qj\";})(),(function f000(){return \"Zj" ascii
    $s7  = "ion f000(){return \"MKa\";})(),(function f000(){return \"Ot\";})(),(function f000(){return \"Ot\";})(),(function f000(){return " ascii
    $s8  = "\";})(),(function f000(){return \"GGn\";})(),(function f000(){return \"DAp\";})(),(function f000(){return \"Sq\";})(),(function " ascii
    $s9  = "){return \"XTn\";})(),(function f000(){return \"ZGq\";})(),(function f000(){return \"ZGq\";})(),(function f000(){return \"ZGq\";" ascii
    $s10 = " \"Kw\";})(),(function f000(){return \"Qz\";})(),(function f000(){return \"ZGq\";})(),(function f000(){return \"Zj\";})(),(funct" ascii
    $s11 = "){return \"MDb\";})(),(function f000(){return \"GGn\";})(),(function f000(){return \"Qz\";})(),(function f000(){return \"Zj\";})" ascii
    $s12 = "{return \"Oe\";})(),(function f000(){return \"Tn\";})(),(function f000(){return \"Br\";})(),(function f000(){return \"GGn\";})()" ascii
    $s13 = "nction f000(){return \"Kw\";})(),(function f000(){return \"OUx\";})(),(function f000(){return \"Qj\";})(),(function f000(){retur" ascii
    $s14 = "(){return \"Yi\";})(),(function f000(){return \"Yi\";})(),(function f000(){return \"ZGq\";})(),(function f000(){return \"Zj\";})" ascii
    $s15 = "(){return \"GGn\";})(),(function f000(){return \"RPt\";})(),(function f000(){return \"ZGq\";})(),(function f000(){return \"KXg\"" ascii
    $s16 = "){return \"GGn\";})(),(function f000(){return \"ZFe\";})(),(function f000(){return \"Rh\";})(),(function f000(){return \"Wy\";})" ascii
    $s17 = "eturn \"Qj\";})(),(function f000(){return \"Lp\";})(),(function f000(){return \"Kw\";})(),(function f000(){return \"Zj\";})(),(f" ascii
    $s18 = "),(function f000(){return \"SEo\";})(),(function f000(){return \"UEg\";})(),(function f000(){return \"KXg\";})(),(function f000(" ascii
    $s19 = "){return \"KXg\";})(),(function f000(){return \"RPt\";})(),(function f000(){return \"ZGq\";})(),(function f000(){return \"TRc\";" ascii
    $s20 = "ion f000(){return \"ZGq\";})(),(function f000(){return \"ZGq\";})(),(function f000(){return \"ZGq\";})(),(function f000(){return" ascii

  condition:
    (uint16(0) == 0x2f0a and (8 of them)
    ) or (all of them)
}