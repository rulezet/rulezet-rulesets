rule _20160921_22314dccf19b7c672f3deae2294f4b16_20160921_b4c84c929547_252 {
  meta:
    description = "datamaliciousorder - from files 20160921_22314dccf19b7c672f3deae2294f4b16.js, 20160921_b4c84c92954782bcf19013150a359ec6.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "9361b0d332b84592c527454959eb22d4191bb17c4d1acc962c192e90e96fc83e"
    hash2       = "deac288c0b80bcd19eff4e9a4bb55e7bdc0f08b0110094a0693c671b47cda285"

  strings:
    $s1  = " \"Km\";})(),(function f000(){return \"Lp\";})(),(function f000(){return \"GGn\";})(),(function f000(){return \"WIj\";})(),(func" ascii
    $s2  = "})(),(function f000(){return \"KXg\";})(),(function f000(){return \"MJq\";})(),(function f000(){return \"Kw\";})(),(function f00" ascii
    $s3  = "),(function f000(){return \"MDb\";})(),(function f000(){return \"DAp\";})(),(function f000(){return \"Tn\";})(),(function f000()" ascii
    $s4  = "(){return \"Uo\";})(),(function f000(){return \"Nv\";})(),(function f000(){return \"Sq\";})(),(function f000(){return \"TKl\";})" ascii
    $s5  = ";})(),(function f000(){return \"Wh\";})(),(function f000(){return \"Wh\";})(),(function f000(){return \"UEg\";})(),(function f00" ascii
    $s6  = " f000(){return \"Br\";})(),(function f000(){return \"Wb\";})(),(function f000(){return \"Wb\";})(),(function f000(){return \"Yi" ascii
    $s7  = "rn \"GGn\";})(),(function f000(){return \"Br\";})(),(function f000(){return \"Ml\";})(),(function f000(){return \"TKp\";})(),(fu" ascii
    $s8  = " \"Tn\";})(),(function f000(){return \"GGn\";})(),(function f000(){return \"Sv\";})(),(function f000(){return \"NYh\";})(),(func" ascii
    $s9  = "tion f000(){return \"MJq\";})(),(function f000(){return \"Qj\";})(),(function f000(){return \"GGn\";})(),(function f000(){return" ascii
    $s10 = "eturn \"Qj\";})(),(function f000(){return \"MDb\";})(),(function f000(){return \"SEo\";})(),(function f000(){return \"Rh\";})()," ascii
    $s11 = "urn \"GGn\";})(),(function f000(){return \"Br\";})(),(function f000(){return \"YTp\";})(),(function f000(){return \"Wb\";})(),(f" ascii
    $s12 = "function f000(){return \"Br\";})(),(function f000(){return \"UEg\";})(),(function f000(){return \"UEg\";})(),(function f000(){re" ascii
    $s13 = "on f000(){return \"Vu\";})(),(function f000(){return \"Sq\";})(),(function f000(){return \"GGn\";})(),(function f000(){return \"" ascii
    $s14 = " f000(){return \"Do\";})(),(function f000(){return \"Kw\";})(),(function f000(){return \"OMd\";})(),(function f000(){return \"GG" ascii
    $s15 = "(function f000(){return \"ZIi\";})(),(function f000(){return \"Mc\";})(),(function f000(){return \"XTn\";})(),(function f000(){r" ascii
    $s16 = "function f000(){return \"Oe\";})(),(function f000(){return \"QDg\";})(),(function f000(){return \"DNa\";})(),(function f000(){re" ascii
    $s17 = "f000(){return \"Yv\";})(),(function f000(){return \"UEg\";})(),(function f000(){return \"Qj\";})(),(function f000(){return \"GGn" ascii
    $s18 = "eturn \"Br\";})(),(function f000(){return \"Yz\";})(),(function f000(){return \"Lo\";})(),(function f000(){return \"Br\";})(),(f" ascii
    $s19 = "(function f000(){return \"GGn\";})(),(function f000(){return \"Sj\";})(),(function f000(){return \"Km\";})(),(function f000(){re" ascii
    $s20 = "turn \"Go\";})(),(function f000(){return \"Sq\";})(),(function f000(){return \"GGn\";})(),(function f000(){return \"WIj\";})(),(" ascii

  condition:
    (uint16(0) == 0x2f0a and (8 of them)
    ) or (all of them)
}