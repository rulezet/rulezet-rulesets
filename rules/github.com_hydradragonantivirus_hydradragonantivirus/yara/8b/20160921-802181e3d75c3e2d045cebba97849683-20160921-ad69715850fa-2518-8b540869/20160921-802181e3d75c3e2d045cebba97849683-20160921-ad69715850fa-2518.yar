rule _20160921_802181e3d75c3e2d045cebba97849683_20160921_ad69715850fa_2518 {
  meta:
    description = "datamaliciousorder - from files 20160921_802181e3d75c3e2d045cebba97849683.js, 20160921_ad69715850fae108d9a16055efb4f51c.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "ab42f16384f05ce6299f1ffd60f980af6ecf1fa2d23befc951797d1d52915400"
    hash2       = "76ed8c5c3ace4ce119f1561d5d61ca2e454da79e9156a8397e72d6eed3a22d74"

  strings:
    $s1 = "\"DYs\";})(),(function f000(){return \"Lp\";})(),(function f000(){return \"Oe\";})(),(function f000(){return \"GGn\";})(),(funct" ascii
    $s2 = ",(function f000(){return \"RPt\";})(),(function f000(){return \"Yi\";})(),(function f000(){return \"Qz\";})(),(function f000(){r" ascii
    $s3 = "nction f000(){return \"GGn\";})(),(function f000(){return \"Br\";})(),(function f000(){return \"TKp\";})(),(function f000(){retu" ascii
    $s4 = "0(){return \"Mu\";})(),(function f000(){return \"Vu\";})(),(function f000(){return \"RPt\";})(),(function f000(){return \"Qz\";}" ascii
    $s5 = "\";})(),(function f000(){return \"RPt\";})(),(function f000(){return \"Yi\";})(),(function f000(){return \"Vu\";})(),(function f" ascii
    $s6 = "turn \"KXg\";})(),(function f000(){return \"Yi\";})(),(function f000(){return \"Vj\";})(),(function f000(){return \"Zj\";})(),(f" ascii
    $s7 = "turn \"Tn\";})(),(function f000(){return \"GGn\";})(),(function f000(){return \"MMz\";})(),(function f000(){return \"Wy\";})(),(" ascii
    $s8 = "\";})(),(function f000(){return \"Vu\";})(),(function f000(){return \"Vj\";})(),(function f000(){return \"RPt\";})(),(function f" ascii

  condition:
    (uint16(0) == 0x2f0a and (all of them)
    ) or (all of them)
}