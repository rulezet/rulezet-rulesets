rule _20160921_ccabe4fce99c1ebb627aa374a501f33c_20160922_b9c8ae1e2648_1139 {
  meta:
    description = "datamaliciousorder - from files 20160921_ccabe4fce99c1ebb627aa374a501f33c.js, 20160922_b9c8ae1e2648708b7b599ba2ac6333c1.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "449fe576ee25f77acba5442d771e770819941d7dbf354b5123ca5211ef743189"
    hash2       = "e2b244eea80e558d4ae468572be8ba3fade8163b0f8751b10ba6ca2263421085"

  strings:
    $s1  = "unction f000(){return \"GGn\";})(),(function f000(){return \"Nv\";})(),(function f000(){return \"DYx\";})(),(function f000(){ret" ascii
    $s2  = ";})(),(function f000(){return \"ZFe\";})(),(function f000(){return \"ZIi\";})(),(function f000(){return \"NBs\";})(),(function f" ascii
    $s3  = "rn \"Vu\";})(),(function f000(){return \"Mc\";})(),(function f000(){return \"TRc\";})(),(function f000(){return \"QDg\";})(),(fu" ascii
    $s4  = "),(function f000(){return \"OUx\";})(),(function f000(){return \"DYs\";})(),(function f000(){return \"BQb\";})(),(function f000(" ascii
    $s5  = "return \"Qa\";})(),(function f000(){return \"DYx\";})(),(function f000(){return \"DIa\";})(),(function f000(){return \"Zj\";})()" ascii
    $s6  = "eturn \"MMz\";})(),(function f000(){return \"MKa\";})(),(function f000(){return \"Ot\";})(),(function f000(){return \"Rh\";})()," ascii
    $s7  = "tion f000(){return \"GGn\";})(),(function f000(){return \"PTi\";})(),(function f000(){return \"Yz\";})(),(function f000(){return" ascii
    $s8  = "(){return \"KDh\";})(),(function f000(){return \"Vu\";})(),(function f000(){return \"TKp\";})(),(function f000(){return \"Do\";}" ascii
    $s9  = "Pt\";})(),(function f000(){return \"TRc\";})(),(function f000(){return \"OUx\";})(),(function f000(){return \"Vu\";})(),(functio" ascii
    $s10 = "i\";})(),(function f000(){return \"PTs\";})(),(function f000(){return \"Iq\";})(),(function f000(){return \"GGn\";})(),(function" ascii
    $s11 = "ion f000(){return \"ZFe\";})(),(function f000(){return \"TKp\";})(),(function f000(){return \"KXg\";})(),(function f000(){return" ascii
    $s12 = "(){return \"DAp\";})(),(function f000(){return \"NYh\";})(),(function f000(){return \"GGn\";})(),(function f000(){return \"MDb\"" ascii
    $s13 = "tion f000(){return \"MMz\";})(),(function f000(){return \"MKa\";})(),(function f000(){return \"Uo\";})(),(function f000(){return" ascii
    $s14 = "ction f000(){return \"Yz\";})(),(function f000(){return \"BMj\";})(),(function f000(){return \"Zj\";})(),(function f000(){return" ascii
    $s15 = " f000(){return \"HJm\";})(),(function f000(){return \"RLk\";})(),(function f000(){return \"Tn\";})(),(function f000(){return \"R" ascii
    $s16 = "tion f000(){return \"SEo\";})(),(function f000(){return \"RVb\";})(),(function f000(){return \"KXg\";})(),(function f000(){retur" ascii
    $s17 = ";})(),(function f000(){return \"MDb\";})(),(function f000(){return \"KDh\";})(),(function f000(){return \"RLk\";})(),(function f" ascii

  condition:
    (uint16(0) == 0x2f0a and (8 of them)
    ) or (all of them)
}