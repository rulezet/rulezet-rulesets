rule _20160921_2fddda42e5911e6501568e734d430149_20160921_b8c98d7e4e5c_367 {
  meta:
    description = "datamaliciousorder - from files 20160921_2fddda42e5911e6501568e734d430149.js, 20160921_b8c98d7e4e5c69c2f4fa4fec37a59dfb.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "39e075f0b6da6e9616ecc55632d12b76e677c40d3e27c38908b71f907b17d8e1"
    hash2       = "f1ea05bc317ec861954db64b30bd293d8ee2f663106d48389d91cfb77247fb1e"

  strings:
    $s1  = " \"OUx\";})(),(function f000(){return \"RPt\";})(),(function f000(){return \"Yi\";})(),(function f000(){return \"Lp\";})(),(func" ascii
    $s2  = " \"Kw\";})(),(function f000(){return \"OUx\";})(),(function f000(){return \"RPt\";})(),(function f000(){return \"ZGq\";})(),(fun" ascii
    $s3  = "f000(){return \"WIj\";})(),(function f000(){return \"Qz\";})(),(function f000(){return \"ZGq\";})(),(function f000(){return \"GG" ascii
    $s4  = "Ij\";})(),(function f000(){return \"Lp\";})(),(function f000(){return \"ZGq\";})(),(function f000(){return \"KXg\";})(),(functio" ascii
    $s5  = "rn \"GGn\";})(),(function f000(){return \"DYs\";})(),(function f000(){return \"Um\";})(),(function f000(){return \"Mt\";})(),(fu" ascii
    $s6  = "ion f000(){return \"Qz\";})(),(function f000(){return \"DIa\";})(),(function f000(){return \"GGn\";})(),(function f000(){return " ascii
    $s7  = "eturn \"GGn\";})(),(function f000(){return \"Ut\";})(),(function f000(){return \"GGn\";})(),(function f000(){return \"XTn\";})()" ascii
    $s8  = "return \"Qj\";})(),(function f000(){return \"Qz\";})(),(function f000(){return \"KXg\";})(),(function f000(){return \"TRc\";})()" ascii
    $s9  = "0(){return \"Lp\";})(),(function f000(){return \"Kw\";})(),(function f000(){return \"Zj\";})(),(function f000(){return \"Do\";})" ascii
    $s10 = "rn \"OUx\";})(),(function f000(){return \"RPt\";})(),(function f000(){return \"Lp\";})(),(function f000(){return \"ZGq\";})(),(f" ascii
    $s11 = "nction f000(){return \"GGn\";})(),(function f000(){return \"RPt\";})(),(function f000(){return \"KXg\";})(),(function f000(){ret" ascii
    $s12 = "00(){return \"Qj\";})(),(function f000(){return \"ZGq\";})(),(function f000(){return \"GGn\";})(),(function f000(){return \"Mu\"" ascii
    $s13 = "ion f000(){return \"RPt\";})(),(function f000(){return \"Lp\";})(),(function f000(){return \"Kw\";})(),(function f000(){return " ascii
    $s14 = "(),(function f000(){return \"Mu\";})(),(function f000(){return \"TKl\";})(),(function f000(){return \"ZGq\";})(),(function f000(" ascii
    $s15 = " f000(){return \"Kw\";})(),(function f000(){return \"Yi\";})(),(function f000(){return \"ZGq\";})(),(function f000(){return \"TR" ascii
    $s16 = " f000(){return \"Lp\";})(),(function f000(){return \"Lp\";})(),(function f000(){return \"GGn\";})(),(function f000(){return \"MD" ascii
    $s17 = "t\";})(),(function f000(){return \"Qj\";})(),(function f000(){return \"Lp\";})(),(function f000(){return \"TRc\";})(),(function " ascii
    $s18 = "urn \"Qj\";})(),(function f000(){return \"Kw\";})(),(function f000(){return \"KXg\";})(),(function f000(){return \"Lp\";})(),(fu" ascii
    $s19 = "){return \"WIj\";})(),(function f000(){return \"TKl\";})(),(function f000(){return \"Qz\";})(),(function f000(){return \"ZGq\";}" ascii
    $s20 = "Tn\";})(),(function f000(){return \"Qz\";})(),(function f000(){return \"ZGq\";})(),(function f000(){return \"RPt\";})(),(functio" ascii

  condition:
    (uint16(0) == 0x2f0a and (8 of them)
    ) or (all of them)
}