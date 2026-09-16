rule _20160921_dc1d9050026f8e96fefca2306b0b5aba_20160921_e98813a05e66_4071 {
  meta:
    description = "datamaliciousorder - from files 20160921_dc1d9050026f8e96fefca2306b0b5aba.js, 20160921_e98813a05e661b621a9d4b3a1d6d901f.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "c6189a2d5bf1254f55c8d7ad46101d9c32dc62eda1d03b19dddb22f049f8965d"
    hash2       = "5b491479317737dd237b9c5bc10e2831e78ae8bbc9ea6a11e5ef5f5bc6c813f8"

  strings:
    $s1 = "f000(){return \"DYs\";})(),(function f000(){return \"Yz\";})(),(function f000(){return \"UEg\";})(),(function f000(){return \"Oe" ascii
    $s2 = " \"WIj\";})(),(function f000(){return \"WIj\";})(),(function f000(){return \"GGn\";})(),(function f000(){return \"Br\";})(),(fun" ascii
    $s3 = "})(),(function f000(){return \"Wy\";})(),(function f000(){return \"DYx\";})(),(function f000(){return \"Vj\";})(),(function f000" ascii
    $s4 = "function f000(){return \"Lp\";})(),(function f000(){return \"Br\";})(),(function f000(){return \"DIa\";})(),(function f000(){ret" ascii
    $s5 = "urn \"DYx\";})(),(function f000(){return \"EZu\";})(),(function f000(){return \"Oe\";})(),(function f000(){return \"Tn\";})(),(f" ascii
    $s6 = "rn \"Br\";})(),(function f000(){return \"Wy\";})(),(function f000(){return \"Wh\";})(),(function f000(){return \"Br\";})(),(func" ascii

  condition:
    (uint16(0) == 0x2f0a and (all of them)
    ) or (all of them)
}