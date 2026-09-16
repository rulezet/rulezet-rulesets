rule _20160921_5775da34d70f97a2d7aa3296f909af35_20160921_ad69715850fa_2454 {
  meta:
    description = "datamaliciousorder - from files 20160921_5775da34d70f97a2d7aa3296f909af35.js, 20160921_ad69715850fae108d9a16055efb4f51c.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "270e1d840937d10ac3eb1fdd04f0fbbbfd31a88a2f316c94c5167a23a2940644"
    hash2       = "76ed8c5c3ace4ce119f1561d5d61ca2e454da79e9156a8397e72d6eed3a22d74"

  strings:
    $s1 = "ion f000(){return \"Vj\";})(),(function f000(){return \"TRc\";})(),(function f000(){return \"GGn\";})(),(function f000(){return " ascii
    $s2 = "f000(){return \"Zj\";})(),(function f000(){return \"Ot\";})(),(function f000(){return \"Do\";})(),(function f000(){return \"MKa" ascii
    $s3 = "n f000(){return \"GGn\";})(),(function f000(){return \"Ug\";})(),(function f000(){return \"WIj\";})(),(function f000(){return \"" ascii
    $s4 = "rn \"UOt\";})(),(function f000(){return \"GGn\";})(),(function f000(){return \"KXg\";})(),(function f000(){return \"Vj\";})(),(f" ascii
    $s5 = "function f000(){return \"TKp\";})(),(function f000(){return \"GGn\";})(),(function f000(){return \"Lp\";})(),(function f000(){re" ascii
    $s6 = "n \"BMj\";})(),(function f000(){return \"DIa\";})(),(function f000(){return \"Zj\";})(),(function f000(){return \"Do\";})(),(fun" ascii
    $s7 = "eturn \"GGn\";})(),(function f000(){return \"RLk\";})(),(function f000(){return \"Qj\";})(),(function f000(){return \"WIj\";})()" ascii
    $s8 = "f000(){return \"KXg\";})(),(function f000(){return \"Kw\";})(),(function f000(){return \"TKl\";})(),(function f000(){return \"OM" ascii

  condition:
    (uint16(0) == 0x2f0a and (all of them)
    ) or (all of them)
}