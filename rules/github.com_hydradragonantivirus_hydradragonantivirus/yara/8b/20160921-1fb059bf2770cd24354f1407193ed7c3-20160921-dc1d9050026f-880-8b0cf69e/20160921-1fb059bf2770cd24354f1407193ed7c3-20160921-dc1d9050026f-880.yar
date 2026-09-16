rule _20160921_1fb059bf2770cd24354f1407193ed7c3_20160921_dc1d9050026f_880 {
  meta:
    description = "datamaliciousorder - from files 20160921_1fb059bf2770cd24354f1407193ed7c3.js, 20160921_dc1d9050026f8e96fefca2306b0b5aba.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "ca19a6205a8df61781b8acbf540faa9dd7bc11338d9b2e4285541a5ac284f620"
    hash2       = "c6189a2d5bf1254f55c8d7ad46101d9c32dc62eda1d03b19dddb22f049f8965d"

  strings:
    $s1  = "ion f000(){return \"GGn\";})(),(function f000(){return \"MBb\";})(),(function f000(){return \"BMj\";})(),(function f000(){return" ascii
    $s2  = "rn \"Vj\";})(),(function f000(){return \"Rh\";})(),(function f000(){return \"GGn\";})(),(function f000(){return \"WIj\";})(),(fu" ascii
    $s3  = "turn \"GGn\";})(),(function f000(){return \"Br\";})(),(function f000(){return \"MBb\";})(),(function f000(){return \"Km\";})(),(" ascii
    $s4  = ";})(),(function f000(){return \"Br\";})(),(function f000(){return \"Rh\";})(),(function f000(){return \"Br\";})(),(function f000" ascii
    $s5  = "ction f000(){return \"Vu\";})(),(function f000(){return \"Oe\";})(),(function f000(){return \"GGn\";})(),(function f000(){return" ascii
    $s6  = "){return \"Tb\";})(),(function f000(){return \"PTs\";})(),(function f000(){return \"SGs\";})(),(function f000(){return \"Kw\";})" ascii
    $s7  = "nction f000(){return \"Br\";})(),(function f000(){return \"RVb\";})(),(function f000(){return \"NYh\";})(),(function f000(){retu" ascii
    $s8  = "})(),(function f000(){return \"GGn\";})(),(function f000(){return \"DAp\";})(),(function f000(){return \"Iq\";})(),(function f00" ascii
    $s9  = "ction f000(){return \"Sq\";})(),(function f000(){return \"Lp\";})(),(function f000(){return \"GGn\";})(),(function f000(){return" ascii
    $s10 = "00(){return \"NBs\";})(),(function f000(){return \"Oe\";})(),(function f000(){return \"Br\";})(),(function f000(){return \"GGn\"" ascii
    $s11 = ")(),(function f000(){return \"GGn\";})(),(function f000(){return \"IAa\";})(),(function f000(){return \"Km\";})(),(function f000" ascii
    $s12 = "{return \"Tn\";})(),(function f000(){return \"GGn\";})(),(function f000(){return \"HJm\";})(),(function f000(){return \"IAa\";})" ascii
    $s13 = ";})(),(function f000(){return \"Yz\";})(),(function f000(){return \"Lp\";})(),(function f000(){return \"GGn\";})(),(function f00" ascii
    $s14 = "nction f000(){return \"RPt\";})(),(function f000(){return \"DYx\";})(),(function f000(){return \"Br\";})(),(function f000(){retu" ascii
    $s15 = "return \"BMj\";})(),(function f000(){return \"DYx\";})(),(function f000(){return \"Br\";})(),(function f000(){return \"GGn\";})(" ascii
    $s16 = " f000(){return \"BMj\";})(),(function f000(){return \"MJq\";})(),(function f000(){return \"Br\";})(),(function f000(){return \"G" ascii
    $s17 = "n \"IPu\";})(),(function f000(){return \"XTn\";})(),(function f000(){return \"GGn\";})(),(function f000(){return \"WIj\";})(),(f" ascii
    $s18 = "n f000(){return \"Br\";})(),(function f000(){return \"Iq\";})(),(function f000(){return \"MJq\";})(),(function f000(){return \"N" ascii
    $s19 = "tion f000(){return \"Tn\";})(),(function f000(){return \"GGn\";})(),(function f000(){return \"Sj\";})(),(function f000(){return " ascii
    $s20 = "0(){return \"Sv\";})(),(function f000(){return \"PTs\";})(),(function f000(){return \"SGs\";})(),(function f000(){return \"GGn\"" ascii

  condition:
    (uint16(0) == 0x2f0a and (8 of them)
    ) or (all of them)
}