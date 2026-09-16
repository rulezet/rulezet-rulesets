rule _20160921_5f5611940db748f8f47ad6671e45ac27_20160921_8ab8e9ec61d8_819 {
  meta:
    description = "datamaliciousorder - from files 20160921_5f5611940db748f8f47ad6671e45ac27.js, 20160921_8ab8e9ec61d829b3b36dc8e0cbc3b477.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "141377c1ea41b7c63633225cdfe610934ccb5630d4fc24157bd25932c56d02e2"
    hash2       = "6302a5443fa0c0309aa33e24b90ed81d05258a2a800cda52321e903fc44e0494"

  strings:
    $s1  = "KDh\";})(),(function f000(){return \"Oe\";})(),(function f000(){return \"GGn\";})(),(function f000(){return \"WIj\";})(),(functi" ascii
    $s2  = "urn \"GGn\";})(),(function f000(){return \"PTs\";})(),(function f000(){return \"DYs\";})(),(function f000(){return \"Mc\";})(),(" ascii
    $s3  = "00(){return \"Br\";})(),(function f000(){return \"BMj\";})(),(function f000(){return \"MJq\";})(),(function f000(){return \"Br\"" ascii
    $s4  = "n \"UEg\";})(),(function f000(){return \"Lp\";})(),(function f000(){return \"MDb\";})(),(function f000(){return \"Nv\";})(),(fun" ascii
    $s5  = "turn \"Tn\";})(),(function f000(){return \"GGn\";})(),(function f000(){return \"RLk\";})(),(function f000(){return \"MJq\";})()," ascii
    $s6  = "on f000(){return \"GGn\";})(),(function f000(){return \"Vu\";})(),(function f000(){return \"Iq\";})(),(function f000(){return \"" ascii
    $s7  = "n f000(){return \"IPu\";})(),(function f000(){return \"OMd\";})(),(function f000(){return \"GGn\";})(),(function f000(){return " ascii
    $s8  = "(){return \"GGn\";})(),(function f000(){return \"Br\";})(),(function f000(){return \"Wh\";})(),(function f000(){return \"BMj\";}" ascii
    $s9  = "s\";})(),(function f000(){return \"Mc\";})(),(function f000(){return \"Qj\";})(),(function f000(){return \"MDb\";})(),(function " ascii
    $s10 = "\";})(),(function f000(){return \"NBs\";})(),(function f000(){return \"MDb\";})(),(function f000(){return \"DYs\";})(),(function" ascii
    $s11 = " f000(){return \"Tn\";})(),(function f000(){return \"GGn\";})(),(function f000(){return \"Oh\";})(),(function f000(){return \"Mt" ascii
    $s12 = "(function f000(){return \"PTs\";})(),(function f000(){return \"Wy\";})(),(function f000(){return \"MDb\";})(),(function f000(){r" ascii
    $s13 = "00(){return \"ZIi\";})(),(function f000(){return \"RVb\";})(),(function f000(){return \"MDb\";})(),(function f000(){return \"Uo" ascii
    $s14 = "f000(){return \"Iq\";})(),(function f000(){return \"Yi\";})(),(function f000(){return \"MDb\";})(),(function f000(){return \"ZIi" ascii
    $s15 = "urn \"PTi\";})(),(function f000(){return \"DYx\";})(),(function f000(){return \"GGn\";})(),(function f000(){return \"MDb\";})()," ascii
    $s16 = "rn \"Br\";})(),(function f000(){return \"TKp\";})(),(function f000(){return \"Yz\";})(),(function f000(){return \"Br\";})(),(fun" ascii
    $s17 = "nction f000(){return \"Yi\";})(),(function f000(){return \"MDb\";})(),(function f000(){return \"Sv\";})(),(function f000(){retur" ascii
    $s18 = "return \"MDb\";})(),(function f000(){return \"DYs\";})(),(function f000(){return \"RLk\";})(),(function f000(){return \"Nx\";})(" ascii
    $s19 = "urn \"Vj\";})(),(function f000(){return \"NYh\";})(),(function f000(){return \"MDb\";})(),(function f000(){return \"Vu\";})(),(f" ascii
    $s20 = "b\";})(),(function f000(){return \"GGn\";})(),(function f000(){return \"Yv\";})(),(function f000(){return \"Nx\";})(),(function " ascii

  condition:
    (uint16(0) == 0x2f0a and (8 of them)
    ) or (all of them)
}