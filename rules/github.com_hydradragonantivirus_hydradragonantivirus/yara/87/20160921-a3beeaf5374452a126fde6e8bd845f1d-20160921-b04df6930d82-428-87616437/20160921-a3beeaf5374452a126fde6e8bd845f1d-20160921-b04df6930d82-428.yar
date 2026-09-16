rule _20160921_a3beeaf5374452a126fde6e8bd845f1d_20160921_b04df6930d82_428 {
  meta:
    description = "datamaliciousorder - from files 20160921_a3beeaf5374452a126fde6e8bd845f1d.js, 20160921_b04df6930d827daddc0cb4f32f5a0ac7.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "b85118fedd76dd449fd30cfd693681aa77891d92c19c3fa0e9dd14f034e867bb"
    hash2       = "20f05e81e91c6d1996527f4c971330eb9446dbb6ad0d88c4d97a9739264f79ba"

  strings:
    $s1  = "unction f000(){return \"Qj\";})(),(function f000(){return \"TRc\";})(),(function f000(){return \"WIj\";})(),(function f000(){ret" ascii
    $s2  = "n \"Kw\";})(),(function f000(){return \"Qz\";})(),(function f000(){return \"Yi\";})(),(function f000(){return \"Qz\";})(),(funct" ascii
    $s3  = " f000(){return \"XTn\";})(),(function f000(){return \"Qj\";})(),(function f000(){return \"Zj\";})(),(function f000(){return \"MM" ascii
    $s4  = "00(){return \"WIj\";})(),(function f000(){return \"KXg\";})(),(function f000(){return \"RPt\";})(),(function f000(){return \"Qj" ascii
    $s5  = "ction f000(){return \"TKl\";})(),(function f000(){return \"KXg\";})(),(function f000(){return \"TKl\";})(),(function f000(){retu" ascii
    $s6  = "\"Yi\";})(),(function f000(){return \"Zj\";})(),(function f000(){return \"KZr\";})(),(function f000(){return \"MMz\";})(),(funct" ascii
    $s7  = "function f000(){return \"Wb\";})(),(function f000(){return \"Do\";})(),(function f000(){return \"WIj\";})(),(function f000(){ret" ascii
    $s8  = " \"Kw\";})(),(function f000(){return \"Zj\";})(),(function f000(){return \"GGn\";})(),(function f000(){return \"MMz\";})(),(func" ascii
    $s9  = "f000(){return \"Qz\";})(),(function f000(){return \"Kw\";})(),(function f000(){return \"GGn\";})(),(function f000(){return \"Ut" ascii
    $s10 = "urn \"Qj\";})(),(function f000(){return \"Kw\";})(),(function f000(){return \"XTn\";})(),(function f000(){return \"Kw\";})(),(fu" ascii
    $s11 = "return \"TKl\";})(),(function f000(){return \"Lp\";})(),(function f000(){return \"Yi\";})(),(function f000(){return \"GGn\";})()" ascii
    $s12 = "){return \"OUx\";})(),(function f000(){return \"Oh\";})(),(function f000(){return \"ZIi\";})(),(function f000(){return \"NBs\";}" ascii
    $s13 = "f000(){return \"UOt\";})(),(function f000(){return \"GGn\";})(),(function f000(){return \"Go\";})(),(function f000(){return \"Um" ascii
    $s14 = "(),(function f000(){return \"Lp\";})(),(function f000(){return \"WIj\";})(),(function f000(){return \"Tb\";})(),(function f000()" ascii
    $s15 = "n \"Qj\";})(),(function f000(){return \"XTn\";})(),(function f000(){return \"TKl\";})(),(function f000(){return \"TRc\";})(),(fu" ascii
    $s16 = "{return \"RPt\";})(),(function f000(){return \"Kw\";})(),(function f000(){return \"Lp\";})(),(function f000(){return \"Zj\";})()" ascii
    $s17 = "(function f000(){return \"BMj\";})(),(function f000(){return \"Yi\";})(),(function f000(){return \"DIa\";})(),(function f000(){r" ascii
    $s18 = "tion f000(){return \"Qj\";})(),(function f000(){return \"Kw\";})(),(function f000(){return \"Kw\";})(),(function f000(){return " ascii
    $s19 = "Gq\";})(),(function f000(){return \"YTp\";})(),(function f000(){return \"Lp\";})(),(function f000(){return \"TRc\";})(),(functio" ascii
    $s20 = "n \"Qz\";})(),(function f000(){return \"Do\";})(),(function f000(){return \"Lp\";})(),(function f000(){return \"KXg\";})(),(func" ascii

  condition:
    (uint16(0) == 0x2f0a and (8 of them)
    ) or (all of them)
}