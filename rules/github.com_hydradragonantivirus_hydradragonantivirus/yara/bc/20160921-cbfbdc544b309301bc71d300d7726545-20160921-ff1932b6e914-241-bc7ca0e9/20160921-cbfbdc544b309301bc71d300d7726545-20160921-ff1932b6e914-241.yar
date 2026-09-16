rule _20160921_cbfbdc544b309301bc71d300d7726545_20160921_ff1932b6e914_241 {
  meta:
    description = "datamaliciousorder - from files 20160921_cbfbdc544b309301bc71d300d7726545.js, 20160921_ff1932b6e91481dd80ff6251296b57fe.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "135f44db2fcd47db2f5b9cd01f10f5c892ae119d904f5cb0ea4bbdaafba92963"
    hash2       = "07e5271d8517f89575dc2737fae5e8da89c7f2f25cd40c68e183d826da6b2bf0"

  strings:
    $s1  = "tion f000(){return \"ZFe\";})(),(function f000(){return \"Qa\";})(),(function f000(){return \"Kw\";})(),(function f000(){return " ascii
    $s2  = "n f000(){return \"ZFe\";})(),(function f000(){return \"KXg\";})(),(function f000(){return \"Kw\";})(),(function f000(){return \"" ascii
    $s3  = "TKl\";})(),(function f000(){return \"ZFe\";})(),(function f000(){return \"KXg\";})(),(function f000(){return \"RPt\";})(),(funct" ascii
    $s4  = " f000(){return \"Kw\";})(),(function f000(){return \"TKl\";})(),(function f000(){return \"Zj\";})(),(function f000(){return \"MM" ascii
    $s5  = "(),(function f000(){return \"RPt\";})(),(function f000(){return \"ZFe\";})(),(function f000(){return \"Yi\";})(),(function f000(" ascii
    $s6  = "ion f000(){return \"KXg\";})(),(function f000(){return \"Qz\";})(),(function f000(){return \"DIa\";})(),(function f000(){return " ascii
    $s7  = "rn \"ZFe\";})(),(function f000(){return \"Qa\";})(),(function f000(){return \"ZFe\";})(),(function f000(){return \"TRc\";})(),(f" ascii
    $s8  = " f000(){return \"GGn\";})(),(function f000(){return \"HJm\";})(),(function f000(){return \"Sq\";})(),(function f000(){return \"Z" ascii
    $s9  = "ction f000(){return \"ZFe\";})(),(function f000(){return \"TKl\";})(),(function f000(){return \"Do\";})(),(function f000(){retur" ascii
    $s10 = "),(function f000(){return \"ZFe\";})(),(function f000(){return \"Yi\";})(),(function f000(){return \"ZFe\";})(),(function f000()" ascii
    $s11 = ",(function f000(){return \"ZFe\";})(),(function f000(){return \"Qa\";})(),(function f000(){return \"XTn\";})(),(function f000(){" ascii
    $s12 = "n \"KXg\";})(),(function f000(){return \"Kw\";})(),(function f000(){return \"Do\";})(),(function f000(){return \"TRc\";})(),(fun" ascii
    $s13 = "x\";})(),(function f000(){return \"ZFe\";})(),(function f000(){return \"TKl\";})(),(function f000(){return \"Yi\";})(),(function" ascii
    $s14 = "tion f000(){return \"ZFe\";})(),(function f000(){return \"TKl\";})(),(function f000(){return \"RPt\";})(),(function f000(){retur" ascii
    $s15 = "ion f000(){return \"XTn\";})(),(function f000(){return \"ZFe\";})(),(function f000(){return \"Zj\";})(),(function f000(){return " ascii
    $s16 = "tion f000(){return \"OUx\";})(),(function f000(){return \"RPt\";})(),(function f000(){return \"XTn\";})(),(function f000(){retur" ascii
    $s17 = "\"GGn\";})(),(function f000(){return \"TKl\";})(),(function f000(){return \"Kw\";})(),(function f000(){return \"ZFe\";})(),(func" ascii
    $s18 = "n\";})(),(function f000(){return \"TKl\";})(),(function f000(){return \"Qa\";})(),(function f000(){return \"Yi\";})(),(function " ascii
    $s19 = "l\";})(),(function f000(){return \"Qa\";})(),(function f000(){return \"Zj\";})(),(function f000(){return \"MMz\";})(),(function " ascii
    $s20 = "n f000(){return \"KXg\";})(),(function f000(){return \"Qa\";})(),(function f000(){return \"TRc\";})(),(function f000(){return \"" ascii

  condition:
    (uint16(0) == 0x2f0a and (8 of them)
    ) or (all of them)
}