rule _20160921_970f1dd445269cda0ba5e6f9fd675983_20160921_a31336f19235_15 {
  meta:
    description = "datamaliciousorder - from files 20160921_970f1dd445269cda0ba5e6f9fd675983.js, 20160921_a31336f192353e1997fed06b582e1aef.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "eb33bb458042e91be0620012d2d05aaafd9742abb0880d1389b5c02b834e9290"
    hash2       = "762774d5263bffcad635355a63715b9cd26c09b53efe134be033e8dff5062b47"

  strings:
    $s1  = "on f000(){return \"MDb\";})(),(function f000(){return \"GGn\";})(),(function f000(){return \"MBb\";})(),(function f000(){return " ascii
    $s2  = "\"TKp\";})(),(function f000(){return \"MDb\";})(),(function f000(){return \"Tb\";})(),(function f000(){return \"Vj\";})(),(funct" ascii
    $s3  = "})(),(function f000(){return \"Yv\";})(),(function f000(){return \"DNa\";})(),(function f000(){return \"SGs\";})(),(function f00" ascii
    $s4  = "n f000(){return \"RPt\";})(),(function f000(){return \"Qa\";})(),(function f000(){return \"KXg\";})(),(function f000(){return \"" ascii
    $s5  = "){return \"WIj\";})(),(function f000(){return \"GGn\";})(),(function f000(){return \"Go\";})(),(function f000(){return \"PTs\";}" ascii
    $s6  = "urn \"Yi\";})(),(function f000(){return \"WIj\";})(),(function f000(){return \"BMj\";})(),(function f000(){return \"Iq\";})(),(f" ascii
    $s7  = "(){return \"Nx\";})(),(function f000(){return \"BQb\";})(),(function f000(){return \"Br\";})(),(function f000(){return \"GGn\";}" ascii
    $s8  = "){return \"PTs\";})(),(function f000(){return \"NBs\";})(),(function f000(){return \"Yi\";})(),(function f000(){return \"DIa\";}" ascii
    $s9  = "n f000(){return \"Sq\";})(),(function f000(){return \"GGn\";})(),(function f000(){return \"QDg\";})(),(function f000(){return \"" ascii
    $s10 = "),(function f000(){return \"Qa\";})(),(function f000(){return \"Do\";})(),(function f000(){return \"KXg\";})(),(function f000(){" ascii
    $s11 = "n \"Qz\";})(),(function f000(){return \"MDb\";})(),(function f000(){return \"Vj\";})(),(function f000(){return \"SGs\";})(),(fun" ascii
    $s12 = " \"ZFe\";})(),(function f000(){return \"XTn\";})(),(function f000(){return \"TKl\";})(),(function f000(){return \"Qz\";})(),(fun" ascii
    $s13 = "on f000(){return \"OMd\";})(),(function f000(){return \"GGn\";})(),(function f000(){return \"DYs\";})(),(function f000(){return " ascii
    $s14 = "n \"KXg\";})(),(function f000(){return \"MDb\";})(),(function f000(){return \"Tb\";})(),(function f000(){return \"PTi\";})(),(fu" ascii
    $s15 = "ZFe\";})(),(function f000(){return \"KXg\";})(),(function f000(){return \"Do\";})(),(function f000(){return \"Zj\";})(),(functio" ascii
    $s16 = ";})(),(function f000(){return \"PTi\";})(),(function f000(){return \"Nx\";})(),(function f000(){return \"Qz\";})(),(function f00" ascii
    $s17 = "{return \"WIj\";})(),(function f000(){return \"KXg\";})(),(function f000(){return \"Qa\";})(),(function f000(){return \"Qa\";})(" ascii
    $s18 = "n \"Qz\";})(),(function f000(){return \"Qa\";})(),(function f000(){return \"KXg\";})(),(function f000(){return \"GGn\";})(),(fun" ascii
    $s19 = "000(){return \"GGn\";})(),(function f000(){return \"DYs\";})(),(function f000(){return \"BQb\";})(),(function f000(){return \"Do" ascii
    $s20 = "unction f000(){return \"GGn\";})(),(function f000(){return \"Br\";})(),(function f000(){return \"UEg\";})(),(function f000(){ret" ascii

  condition:
    (uint16(0) == 0x2f0a and (8 of them)
    ) or (all of them)
}