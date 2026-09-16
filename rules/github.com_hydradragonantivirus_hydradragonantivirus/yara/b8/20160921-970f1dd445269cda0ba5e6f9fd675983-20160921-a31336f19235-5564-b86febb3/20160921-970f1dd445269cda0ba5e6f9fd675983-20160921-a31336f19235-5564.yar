rule _20160921_970f1dd445269cda0ba5e6f9fd675983_20160921_a31336f19235_5564 {
  meta:
    description = "datamaliciousorder - from files 20160921_970f1dd445269cda0ba5e6f9fd675983.js, 20160921_a31336f192353e1997fed06b582e1aef.js, 20160921_f11c35e3159325debfd0a307299c4087.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "eb33bb458042e91be0620012d2d05aaafd9742abb0880d1389b5c02b834e9290"
    hash2       = "762774d5263bffcad635355a63715b9cd26c09b53efe134be033e8dff5062b47"
    hash3       = "f18be6e3d6cc83db6a4204656661ec0e213eded871d58d50b9d2c8b212b94cbd"

  strings:
    $s1 = "0(){return \"DNa\";})(),(function f000(){return \"Um\";})(),(function f000(){return \"Sq\";})(),(function f000(){return \"Yi\";}" ascii
    $s2 = "000(){return \"Yv\";})(),(function f000(){return \"Km\";})(),(function f000(){return \"RPt\";})(),(function f000(){return \"GGn" ascii
    $s3 = "rn \"Qp\";})(),(function f000(){return \"GGn\";})(),(function f000(){return \"IAa\";})(),(function f000(){return \"Nv\";})(),(fu" ascii
    $s4 = "000(){return \"Rh\";})(),(function f000(){return \"Yi\";})(),(function f000(){return \"OUx\";})(),(function f000(){return \"IAa" ascii
    $s5 = "000(){return \"ZFe\";})(),(function f000(){return \"Qa\";})(),(function f000(){return \"XTn\";})(),(function f000(){return \"Qa" ascii

  condition:
    (uint16(0) == 0x2f0a and (all of them)
    ) or (all of them)
}