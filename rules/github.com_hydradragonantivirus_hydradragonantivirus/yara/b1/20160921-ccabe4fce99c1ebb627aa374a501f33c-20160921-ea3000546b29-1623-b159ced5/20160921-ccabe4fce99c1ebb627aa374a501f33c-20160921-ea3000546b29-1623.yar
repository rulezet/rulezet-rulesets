rule _20160921_ccabe4fce99c1ebb627aa374a501f33c_20160921_ea3000546b29_1623 {
  meta:
    description = "datamaliciousorder - from files 20160921_ccabe4fce99c1ebb627aa374a501f33c.js, 20160921_ea3000546b29aee563be9d58318d1857.js, 20160921_f5decbca2e5a35bbb5c42091c1b0c30e.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "449fe576ee25f77acba5442d771e770819941d7dbf354b5123ca5211ef743189"
    hash2       = "eb46ac22bc2e86a5bacf6fbfffe3a746600369a5d28c84d095b1269bcdfe9cc6"
    hash3       = "5fe03908bd7d860f1260a3264b2e10de3115d24242a095cf4c0b73e7934ce89e"

  strings:
    $s1  = "00(){return \"TKp\";})(),(function f000(){return \"GGn\";})(),(function f000(){return \"OUx\";})(),(function f000(){return \"TRc" ascii
    $s2  = "(),(function f000(){return \"GGn\";})(),(function f000(){return \"BIj\";})(),(function f000(){return \"Tn\";})(),(function f000(" ascii
    $s3  = "n \"MDb\";})(),(function f000(){return \"GGn\";})(),(function f000(){return \"Yv\";})(),(function f000(){return \"Nv\";})(),(fun" ascii
    $s4  = "nction f000(){return \"DYx\";})(),(function f000(){return \"TKp\";})(),(function f000(){return \"GGn\";})(),(function f000(){ret" ascii
    $s5  = "Dh\";})(),(function f000(){return \"Oh\";})(),(function f000(){return \"Iq\";})(),(function f000(){return \"QDg\";})(),(function" ascii
    $s6  = "\";})(),(function f000(){return \"DIa\";})(),(function f000(){return \"GGn\";})(),(function f000(){return \"Fs\";})(),(function " ascii
    $s7  = "urn \"Rh\";})(),(function f000(){return \"Yi\";})(),(function f000(){return \"Zj\";})(),(function f000(){return \"MMz\";})(),(fu" ascii
    $s8  = "n f000(){return \"Sq\";})(),(function f000(){return \"WIj\";})(),(function f000(){return \"QDg\";})(),(function f000(){return \"" ascii
    $s9  = "return \"GGn\";})(),(function f000(){return \"RPt\";})(),(function f000(){return \"Do\";})(),(function f000(){return \"Do\";})()" ascii
    $s10 = "turn \"Sq\";})(),(function f000(){return \"GGn\";})(),(function f000(){return \"Sj0\";})(),(function f000(){return \"WIj\";})()," ascii
    $s11 = "(function f000(){return \"Zj\";})(),(function f000(){return \"KZr\";})(),(function f000(){return \"Zj\";})(),(function f000(){re" ascii
    $s12 = "return \"Ot\";})(),(function f000(){return \"Ot\";})(),(function f000(){return \"ZFe\";})(),(function f000(){return \"Yv\";})()," ascii

  condition:
    (uint16(0) == 0x2f0a and (8 of them)
    ) or (all of them)
}