rule _20160921_970f1dd445269cda0ba5e6f9fd675983_20160921_a31336f19235_3095 {
  meta:
    description = "datamaliciousorder - from files 20160921_970f1dd445269cda0ba5e6f9fd675983.js, 20160921_a31336f192353e1997fed06b582e1aef.js, 20160921_ff1932b6e91481dd80ff6251296b57fe.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "eb33bb458042e91be0620012d2d05aaafd9742abb0880d1389b5c02b834e9290"
    hash2       = "762774d5263bffcad635355a63715b9cd26c09b53efe134be033e8dff5062b47"
    hash3       = "07e5271d8517f89575dc2737fae5e8da89c7f2f25cd40c68e183d826da6b2bf0"

  strings:
    $s1 = "){return \"HJm\";})(),(function f000(){return \"BQb\";})(),(function f000(){return \"GGn\";})(),(function f000(){return \"MDb\";" ascii
    $s2 = " \"Lo\";})(),(function f000(){return \"MDb\";})(),(function f000(){return \"ZGq\";})(),(function f000(){return \"MJq\";})(),(fun" ascii
    $s3 = "(){return \"Qa\";})(),(function f000(){return \"MDb\";})(),(function f000(){return \"PTs\";})(),(function f000(){return \"Nv\";}" ascii
    $s4 = "00(){return \"Do\";})(),(function f000(){return \"MDb\";})(),(function f000(){return \"PTi\";})(),(function f000(){return \"Km\"" ascii
    $s5 = "unction f000(){return \"MDb\";})(),(function f000(){return \"Um\";})(),(function f000(){return \"NBs\";})(),(function f000(){ret" ascii
    $s6 = "),(function f000(){return \"QDg\";})(),(function f000(){return \"Vu\";})(),(function f000(){return \"Oh\";})(),(function f000(){" ascii
    $s7 = "MDb\";})(),(function f000(){return \"BMj\";})(),(function f000(){return \"Sv\";})(),(function f000(){return \"NYh\";})(),(functi" ascii

  condition:
    (uint16(0) == 0x2f0a and (all of them)
    ) or (all of them)
}