rule _20160921_8a6f0879f250e6c15d2c7fa51d20505b_20160921_8dac417cb433_5499 {
  meta:
    description = "datamaliciousorder - from files 20160921_8a6f0879f250e6c15d2c7fa51d20505b.js, 20160921_8dac417cb4331fdefcd724e5c4563731.js, 20160921_970f1dd445269cda0ba5e6f9fd675983.js, 20160921_a31336f192353e1997fed06b582e1aef.js, 20160921_c6163df7a6dda28826544197fc8ddc4f.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "221e50c91cd5c3d541d89b6c9999d61bacb186433ba85ae94088851587c25391"
    hash2       = "4ab6c9959d63ff05f6b1074253866e4ba4ca6148b9d820313ac79da48c63d90e"
    hash3       = "eb33bb458042e91be0620012d2d05aaafd9742abb0880d1389b5c02b834e9290"
    hash4       = "762774d5263bffcad635355a63715b9cd26c09b53efe134be033e8dff5062b47"
    hash5       = "c0d0b12b3c6fc559a577159775ce104e897b9b5c0422b945c7c097dd53710fe8"

  strings:
    $s1 = "(){return \"ZFe\";})(),(function f000(){return \"XTn\";})(),(function f000(){return \"TRc\";})(),(function f000(){return \"WIj\"" ascii
    $s2 = "n \"OUx\";})(),(function f000(){return \"RPt\";})(),(function f000(){return \"ZFe\";})(),(function f000(){return \"RPt\";})(),(f" ascii
    $s3 = "(function f000(){return \"ZFe\";})(),(function f000(){return \"TKl\";})(),(function f000(){return \"Do\";})(),(function f000(){r" ascii
    $s4 = "),(function f000(){return \"TKl\";})(),(function f000(){return \"Qa\";})(),(function f000(){return \"TRc\";})(),(function f000()" ascii
    $s5 = ")(),(function f000(){return \"Yi\";})(),(function f000(){return \"TRc\";})(),(function f000(){return \"QDg\";})(),(function f000" ascii

  condition:
    (uint16(0) == 0x2f0a and (all of them)
    ) or (all of them)
}