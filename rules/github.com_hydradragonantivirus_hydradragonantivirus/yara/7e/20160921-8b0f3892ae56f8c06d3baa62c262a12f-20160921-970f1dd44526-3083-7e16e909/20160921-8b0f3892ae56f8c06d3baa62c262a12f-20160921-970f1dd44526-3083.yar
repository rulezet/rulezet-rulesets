rule _20160921_8b0f3892ae56f8c06d3baa62c262a12f_20160921_970f1dd44526_3083 {
  meta:
    description = "datamaliciousorder - from files 20160921_8b0f3892ae56f8c06d3baa62c262a12f.js, 20160921_970f1dd445269cda0ba5e6f9fd675983.js, 20160921_a31336f192353e1997fed06b582e1aef.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "96514db18a22f5e5bde10feb1f6b426e5772d0f7e76f227e8d49a7a00bfb01b7"
    hash2       = "eb33bb458042e91be0620012d2d05aaafd9742abb0880d1389b5c02b834e9290"
    hash3       = "762774d5263bffcad635355a63715b9cd26c09b53efe134be033e8dff5062b47"

  strings:
    $s1 = "QDg\";})(),(function f000(){return \"DYs\";})(),(function f000(){return \"IAa\";})(),(function f000(){return \"Sq\";})(),(functi" ascii
    $s2 = "urn \"KXg\";})(),(function f000(){return \"Qa\";})(),(function f000(){return \"Zj\";})(),(function f000(){return \"MMz\";})(),(f" ascii
    $s3 = "ion f000(){return \"OUx\";})(),(function f000(){return \"ZFe\";})(),(function f000(){return \"TKl\";})(),(function f000(){return" ascii
    $s4 = "),(function f000(){return \"DNa\";})(),(function f000(){return \"NYh\";})(),(function f000(){return \"Qa\";})(),(function f000()" ascii
    $s5 = "eturn \"GGn\";})(),(function f000(){return \"Sj\";})(),(function f000(){return \"GGn\";})(),(function f000(){return \"GGn\";})()" ascii
    $s6 = "ction f000(){return \"Ot\";})(),(function f000(){return \"Ot\";})(),(function f000(){return \"Ot\";})(),(function f000(){return " ascii
    $s7 = "(),(function f000(){return \"Do\";})(),(function f000(){return \"ZFe\";})(),(function f000(){return \"TRc\";})(),(function f000(" ascii

  condition:
    (uint16(0) == 0x2f0a and (all of them)
    ) or (all of them)
}