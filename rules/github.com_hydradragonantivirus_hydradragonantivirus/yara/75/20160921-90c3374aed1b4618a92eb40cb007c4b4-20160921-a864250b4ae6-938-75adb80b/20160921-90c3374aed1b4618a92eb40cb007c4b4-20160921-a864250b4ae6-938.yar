rule _20160921_90c3374aed1b4618a92eb40cb007c4b4_20160921_a864250b4ae6_938 {
  meta:
    description = "datamaliciousorder - from files 20160921_90c3374aed1b4618a92eb40cb007c4b4.js, 20160921_a864250b4ae6162ed0d7a2f3ed785d46.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "42b3d35e818b5b373b42427cc936c0a099078535d6f37eb5d4dc22b8ac1ee151"
    hash2       = "f64f9f9fd1a5e4b096281bd9733f52c453683cc9032801264dd73f202b17964f"

  strings:
    $s1  = "Pu\";})(),(function f000(){return \"Lp\";})(),(function f000(){return \"GGn\";})(),(function f000(){return \"MDb\";})(),(functio" ascii
    $s2  = "000(){return \"Vu\";})(),(function f000(){return \"Sq\";})(),(function f000(){return \"Ml\";})(),(function f000(){return \"MBb\"" ascii
    $s3  = "(),(function f000(){return \"Do\";})(),(function f000(){return \"TKl\";})(),(function f000(){return \"DIa\";})(),(function f000(" ascii
    $s4  = "ion f000(){return \"Yv\";})(),(function f000(){return \"Sq\";})(),(function f000(){return \"KXg\";})(),(function f000(){return " ascii
    $s5  = "on f000(){return \"Tn\";})(),(function f000(){return \"GGn\";})(),(function f000(){return \"Vu\";})(),(function f000(){return \"" ascii
    $s6  = "\"SEo\";})(),(function f000(){return \"ZGq\";})(),(function f000(){return \"DYx\";})(),(function f000(){return \"TRc\";})(),(fun" ascii
    $s7  = "ction f000(){return \"Yi\";})(),(function f000(){return \"Do\";})(),(function f000(){return \"GGn\";})(),(function f000(){return" ascii
    $s8  = "rn \"KXg\";})(),(function f000(){return \"Lp\";})(),(function f000(){return \"GGn\";})(),(function f000(){return \"Qp\";})(),(fu" ascii
    $s9  = "})(),(function f000(){return \"KXg\";})(),(function f000(){return \"WIj\";})(),(function f000(){return \"SEo\";})(),(function f0" ascii
    $s10 = "ction f000(){return \"Vj\";})(),(function f000(){return \"Nx\";})(),(function f000(){return \"OMd\";})(),(function f000(){return" ascii
    $s11 = " \"Ot\";})(),(function f000(){return \"Ot\";})(),(function f000(){return \"Ot\";})(),(function f000(){return \"Um\";})(),(functi" ascii
    $s12 = "n f000(){return \"Ot\";})(),(function f000(){return \"Ot\";})(),(function f000(){return \"Go\";})(),(function f000(){return \"ZI" ascii
    $s13 = "eturn \"Ot\";})(),(function f000(){return \"Ot\";})(),(function f000(){return \"Ot\";})(),(function f000(){return \"KZr\";})(),(" ascii
    $s14 = "nction f000(){return \"MDb\";})(),(function f000(){return \"GGn\";})(),(function f000(){return \"MBb\";})(),(function f000(){ret" ascii
    $s15 = "n\";})(),(function f000(){return \"HJm\";})(),(function f000(){return \"YTp\";})(),(function f000(){return \"XTn\";})(),(functio" ascii
    $s16 = "000(){return \"Qp\";})(),(function f000(){return \"GGn\";})(),(function f000(){return \"DYs\";})(),(function f000(){return \"Yv" ascii
    $s17 = "000(){return \"DNa\";})(),(function f000(){return \"Oe\";})(),(function f000(){return \"Wy\";})(),(function f000(){return \"PTs" ascii
    $s18 = "){return \"GGn\";})(),(function f000(){return \"ZIi\";})(),(function f000(){return \"DYs\";})(),(function f000(){return \"YTp\";" ascii
    $s19 = ",(function f000(){return \"Iq\";})(),(function f000(){return \"Do\";})(),(function f000(){return \"OUx\";})(),(function f000(){r" ascii
    $s20 = "on f000(){return \"Lp\";})(),(function f000(){return \"DIa\";})(),(function f000(){return \"GGn\";})(),(function f000(){return " ascii

  condition:
    (uint16(0) == 0x2f0a and (8 of them)
    ) or (all of them)
}