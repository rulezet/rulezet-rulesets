rule _20160921_970f1dd445269cda0ba5e6f9fd675983_20160921_a31336f19235_2545 {
  meta:
    description = "datamaliciousorder - from files 20160921_970f1dd445269cda0ba5e6f9fd675983.js, 20160921_a31336f192353e1997fed06b582e1aef.js, 20160921_f1b8df0ab75abc0c2b3be738559f2ab3.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "eb33bb458042e91be0620012d2d05aaafd9742abb0880d1389b5c02b834e9290"
    hash2       = "762774d5263bffcad635355a63715b9cd26c09b53efe134be033e8dff5062b47"
    hash3       = "dfdf24fc382cd60cf8d9c01ff0bca33ee060801ad2bd963895209ac610525301"

  strings:
    $s1 = "function f000(){return \"SEo\";})(),(function f000(){return \"Mc\";})(),(function f000(){return \"Do\";})(),(function f000(){ret" ascii
    $s2 = "){return \"Rh\";})(),(function f000(){return \"DYx\";})(),(function f000(){return \"MJq\";})(),(function f000(){return \"Br\";})" ascii
    $s3 = "),(function f000(){return \"GGn\";})(),(function f000(){return \"Br\";})(),(function f000(){return \"Qz\";})(),(function f000(){" ascii
    $s4 = " \"Yz\";})(),(function f000(){return \"SGs\";})(),(function f000(){return \"TKp\";})(),(function f000(){return \"Yz\";})(),(func" ascii
    $s5 = "rn \"Br\";})(),(function f000(){return \"Fs\";})(),(function f000(){return \"Wh\";})(),(function f000(){return \"Br\";})(),(func" ascii
    $s6 = "ion f000(){return \"RVb\";})(),(function f000(){return \"Lo\";})(),(function f000(){return \"Br\";})(),(function f000(){return " ascii
    $s7 = " \"Wb\";})(),(function f000(){return \"Br\";})(),(function f000(){return \"GGn\";})(),(function f000(){return \"MDb\";})(),(func" ascii
    $s8 = "ion f000(){return \"Br\";})(),(function f000(){return \"DYx\";})(),(function f000(){return \"KXg\";})(),(function f000(){return " ascii

  condition:
    (uint16(0) == 0x2f0a and (all of them)
    ) or (all of them)
}