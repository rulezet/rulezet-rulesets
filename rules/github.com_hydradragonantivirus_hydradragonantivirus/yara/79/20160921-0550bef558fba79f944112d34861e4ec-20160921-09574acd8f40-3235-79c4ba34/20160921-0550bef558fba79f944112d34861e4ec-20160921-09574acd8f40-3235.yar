rule _20160921_0550bef558fba79f944112d34861e4ec_20160921_09574acd8f40_3235 {
  meta:
    description = "datamaliciousorder - from files 20160921_0550bef558fba79f944112d34861e4ec.js, 20160921_09574acd8f408e24693e435b8c769e04.js, 20160921_ded524cdc972424d0fa8254648795d71.js, 20160921_e432cba10cde369693d6b125dda112c7.js, 20160921_f1aea308b2000a8d722d0f21c756fabf.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "7cc46901b4b691df366f68f1812df531215964f5150686b06997f1f49b536a1c"
    hash2       = "502f3f7db781b4ecddec50bed418f60953253591a8d3d5ab1aa2cc3352cd6821"
    hash3       = "09c4ea683259322d1696083646a9b96190b4796e8b3fdf91ba2bf4f6296afaa9"
    hash4       = "0f0aa2d80d649fb44a67c6ec77b95eb26709057f543ca215edf15a9bcc4bae4b"
    hash5       = "3175e432bce3be89acef4ff7215de666ea47cac857c8c07ff649c1cdd5484103"

  strings:
    $s1 = "00(){return \"Oe\";})(),(function f000(){return \"Wy\";})(),(function f000(){return \"PTs\";})(),(function f000(){return \"Iq\";" ascii
    $s2 = " \"UEg\";})(),(function f000(){return \"DYx\";})(),(function f000(){return \"Ml\";})(),(function f000(){return \"DNa\";})(),(fun" ascii
    $s3 = "ction f000(){return \"DYx\";})(),(function f000(){return \"Tn\";})(),(function f000(){return \"Wy\";})(),(function f000(){return" ascii
    $s4 = "nction f000(){return \"BQb\";})(),(function f000(){return \"Oe\";})(),(function f000(){return \"QDg\";})(),(function f000(){retu" ascii
    $s5 = "a\";})(),(function f000(){return \"Vj\";})(),(function f000(){return \"Nx\";})(),(function f000(){return \"DIa\";})(),(function " ascii
    $s6 = " f000(){return \"GGn\";})(),(function f000(){return \"Vu\";})(),(function f000(){return \"Sq\";})(),(function f000(){return \"GG" ascii

  condition:
    (uint16(0) == 0x2f0a and (all of them)
    ) or (all of them)
}