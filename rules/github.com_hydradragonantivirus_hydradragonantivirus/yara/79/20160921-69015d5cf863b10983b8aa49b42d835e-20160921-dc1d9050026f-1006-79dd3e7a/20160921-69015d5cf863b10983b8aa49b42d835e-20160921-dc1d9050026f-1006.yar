rule _20160921_69015d5cf863b10983b8aa49b42d835e_20160921_dc1d9050026f_1006 {
  meta:
    description = "datamaliciousorder - from files 20160921_69015d5cf863b10983b8aa49b42d835e.js, 20160921_dc1d9050026f8e96fefca2306b0b5aba.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "797bada2609e8fc67a8ede267e9fcce2fc817f630e6fe62c7953cc722eea6d2c"
    hash2       = "c6189a2d5bf1254f55c8d7ad46101d9c32dc62eda1d03b19dddb22f049f8965d"

  strings:
    $s1  = "eturn \"ZGq\";})(),(function f000(){return \"Wb\";})(),(function f000(){return \"Do\";})(),(function f000(){return \"WIj\";})()," ascii
    $s2  = "rn \"Tn\";})(),(function f000(){return \"GGn\";})(),(function f000(){return \"DYs\";})(),(function f000(){return \"IPu\";})(),(f" ascii
    $s3  = "\"UEg\";})(),(function f000(){return \"YTp\";})(),(function f000(){return \"Sq\";})(),(function f000(){return \"Yz\";})(),(funct" ascii
    $s4  = "on f000(){return \"Um\";})(),(function f000(){return \"Qa\";})(),(function f000(){return \"Yz\";})(),(function f000(){return \"G" ascii
    $s5  = "00(){return \"GGn\";})(),(function f000(){return \"ZIi\";})(),(function f000(){return \"Nx\";})(),(function f000(){return \"GGn" ascii
    $s6  = "on f000(){return \"Br\";})(),(function f000(){return \"BQb\";})(),(function f000(){return \"Oe\";})(),(function f000(){return \"" ascii
    $s7  = "\";})(),(function f000(){return \"Br\";})(),(function f000(){return \"Lp\";})(),(function f000(){return \"Yi\";})(),(function f0" ascii
    $s8  = "ion f000(){return \"GGn\";})(),(function f000(){return \"Oh\";})(),(function f000(){return \"NBs\";})(),(function f000(){return " ascii
    $s9  = "000(){return \"GGn\";})(),(function f000(){return \"Oh\";})(),(function f000(){return \"Qa\";})(),(function f000(){return \"NYh" ascii
    $s10 = "f000(){return \"Tn\";})(),(function f000(){return \"GGn\";})(),(function f000(){return \"SEo\";})(),(function f000(){return \"KD" ascii
    $s11 = "0(){return \"Do\";})(),(function f000(){return \"Kw\";})(),(function f000(){return \"OMd\";})(),(function f000(){return \"GGn\";" ascii
    $s12 = "ction f000(){return \"NYh\";})(),(function f000(){return \"Do\";})(),(function f000(){return \"GGn\";})(),(function f000(){retur" ascii
    $s13 = "(){return \"MDb\";})(),(function f000(){return \"GGn\";})(),(function f000(){return \"ZIi\";})(),(function f000(){return \"Nx\";" ascii
    $s14 = "eturn \"ZIi\";})(),(function f000(){return \"BMj\";})(),(function f000(){return \"Lp\";})(),(function f000(){return \"GGn\";})()" ascii
    $s15 = "){return \"Tn\";})(),(function f000(){return \"GGn\";})(),(function f000(){return \"ZGq\";})(),(function f000(){return \"ZFe\";}" ascii
    $s16 = "on f000(){return \"MDb\";})(),(function f000(){return \"GGn\";})(),(function f000(){return \"Yv\";})(),(function f000(){return " ascii
    $s17 = "Dh\";})(),(function f000(){return \"Nv\";})(),(function f000(){return \"BMj\";})(),(function f000(){return \"Lp\";})(),(function" ascii
    $s18 = "turn \"Tn\";})(),(function f000(){return \"GGn\";})(),(function f000(){return \"ZIi\";})(),(function f000(){return \"Rh\";})(),(" ascii
    $s19 = "unction f000(){return \"SEo\";})(),(function f000(){return \"Tn\";})(),(function f000(){return \"GGn\";})(),(function f000(){ret" ascii

  condition:
    (uint16(0) == 0x2f0a and (8 of them)
    ) or (all of them)
}