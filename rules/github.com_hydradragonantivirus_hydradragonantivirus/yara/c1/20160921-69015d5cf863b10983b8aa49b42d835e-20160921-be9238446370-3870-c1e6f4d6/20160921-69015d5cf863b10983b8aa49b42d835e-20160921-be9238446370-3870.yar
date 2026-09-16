rule _20160921_69015d5cf863b10983b8aa49b42d835e_20160921_be9238446370_3870 {
  meta:
    description = "datamaliciousorder - from files 20160921_69015d5cf863b10983b8aa49b42d835e.js, 20160921_be923844637026740bc9e5a4aad21ebe.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "797bada2609e8fc67a8ede267e9fcce2fc817f630e6fe62c7953cc722eea6d2c"
    hash2       = "f50e7368497d3ab714aae3798280c1b53ff9f91f0081f1eafa0b9e23e4928336"

  strings:
    $s1 = "rn \"Tn\";})(),(function f000(){return \"DYs\";})(),(function f000(){return \"Yz\";})(),(function f000(){return \"UEg\";})(),(fu" ascii
    $s2 = "0(){return \"TKl\";})(),(function f000(){return \"Lp\";})(),(function f000(){return \"Br\";})(),(function f000(){return \"DIa\";" ascii
    $s3 = "ion f000(){return \"Ml\";})(),(function f000(){return \"Wy\";})(),(function f000(){return \"DYx\";})(),(function f000(){return " ascii
    $s4 = "(),(function f000(){return \"DYx\";})(),(function f000(){return \"EZu\";})(),(function f000(){return \"Oe\";})(),(function f000(" ascii
    $s5 = " \"Br\";})(),(function f000(){return \"Yz\";})(),(function f000(){return \"MJq\";})(),(function f000(){return \"YTp\";})(),(func" ascii
    $s6 = "000(){return \"Oe\";})(),(function f000(){return \"QDg\";})(),(function f000(){return \"DIa\";})(),(function f000(){return \"GGn" ascii

  condition:
    (uint16(0) == 0x2f0a and (all of them)
    ) or (all of them)
}