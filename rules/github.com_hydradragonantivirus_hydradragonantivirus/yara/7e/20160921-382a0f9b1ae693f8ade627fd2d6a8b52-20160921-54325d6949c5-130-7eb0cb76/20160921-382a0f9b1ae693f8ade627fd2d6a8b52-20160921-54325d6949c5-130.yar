rule _20160921_382a0f9b1ae693f8ade627fd2d6a8b52_20160921_54325d6949c5_130 {
  meta:
    description = "datamaliciousorder - from files 20160921_382a0f9b1ae693f8ade627fd2d6a8b52.js, 20160921_54325d6949c5c03d42a42e11b24dee5c.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "4170edc38601b30ac37c9e43a569e4e01000505e73d89702266efb685dc6a8ac"
    hash2       = "0fa3791b48292bf705ed06d701118840e9c87ae1f9ac323fe09b8ad04cedc171"

  strings:
    $s1  = ";})(),(function f000(){return \"TKl\";})(),(function f000(){return \"TRc\";})(),(function f000(){return \"Wh\";})(),(function f0" ascii
    $s2  = ";})(),(function f000(){return \"GGn\";})(),(function f000(){return \"Sj\";})(),(function f000(){return \"Rh\";})(),(function f00" ascii
    $s3  = " \"Sv\";})(),(function f000(){return \"Wb\";})(),(function f000(){return \"ZGq\";})(),(function f000(){return \"TRc\";})(),(func" ascii
    $s4  = " \"Tn\";})(),(function f000(){return \"TKp\";})(),(function f000(){return \"GGn\";})(),(function f000(){return \"DNa\";})(),(fun" ascii
    $s5  = "ction f000(){return \"GGn\";})(),(function f000(){return \"DNa\";})(),(function f000(){return \"Tn\";})(),(function f000(){retur" ascii
    $s6  = "n f000(){return \"Yi\";})(),(function f000(){return \"ZGq\";})(),(function f000(){return \"RPt\";})(),(function f000(){return \"" ascii
    $s7  = "return \"MDb\";})(),(function f000(){return \"MMz\";})(),(function f000(){return \"Lo\";})(),(function f000(){return \"TKl\";})(" ascii
    $s8  = "x\";})(),(function f000(){return \"Qz\";})(),(function f000(){return \"Zj\";})(),(function f000(){return \"Do\";})(),(function f" ascii
    $s9  = "return \"GGn\";})(),(function f000(){return \"PTi\";})(),(function f000(){return \"MMz\";})(),(function f000(){return \"Wb\";})(" ascii
    $s10 = "{return \"GGn\";})(),(function f000(){return \"Br\";})(),(function f000(){return \"Yz\";})(),(function f000(){return \"Ml\";})()" ascii
    $s11 = "on f000(){return \"GGn\";})(),(function f000(){return \"QDg\";})(),(function f000(){return \"TKl\";})(),(function f000(){return " ascii
    $s12 = "turn \"OUx\";})(),(function f000(){return \"RPt\";})(),(function f000(){return \"ZGq\";})(),(function f000(){return \"Qj\";})()," ascii
    $s13 = "\"OUx\";})(),(function f000(){return \"Um\";})(),(function f000(){return \"ZIi\";})(),(function f000(){return \"Rh\";})(),(funct" ascii
    $s14 = "urn \"GGn\";})(),(function f000(){return \"Go\";})(),(function f000(){return \"DYx\";})(),(function f000(){return \"GGn\";})(),(" ascii
    $s15 = "ction f000(){return \"Sj\";})(),(function f000(){return \"ZIi\";})(),(function f000(){return \"IPu\";})(),(function f000(){retur" ascii
    $s16 = "(function f000(){return \"Qz\";})(),(function f000(){return \"ZGq\";})(),(function f000(){return \"RPt\";})(),(function f000(){r" ascii
    $s17 = "nction f000(){return \"SGs\";})(),(function f000(){return \"RPt\";})(),(function f000(){return \"TRc\";})(),(function f000(){ret" ascii
    $s18 = "000(){return \"Mu\";})(),(function f000(){return \"XTn\";})(),(function f000(){return \"KXg\";})(),(function f000(){return \"ZGq" ascii
    $s19 = "{return \"RPt\";})(),(function f000(){return \"Lp\";})(),(function f000(){return \"ZGq\";})(),(function f000(){return \"TRc\";})" ascii
    $s20 = "(){return \"GGn\";})(),(function f000(){return \"RLk\";})(),(function f000(){return \"Qa\";})(),(function f000(){return \"Lo\";}" ascii

  condition:
    (uint16(0) == 0x2f0a and (8 of them)
    ) or (all of them)
}