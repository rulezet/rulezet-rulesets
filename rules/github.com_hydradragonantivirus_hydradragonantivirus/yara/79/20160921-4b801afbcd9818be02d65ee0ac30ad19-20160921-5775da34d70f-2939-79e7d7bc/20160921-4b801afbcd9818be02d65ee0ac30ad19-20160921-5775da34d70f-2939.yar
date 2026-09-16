rule _20160921_4b801afbcd9818be02d65ee0ac30ad19_20160921_5775da34d70f_2939 {
  meta:
    description = "datamaliciousorder - from files 20160921_4b801afbcd9818be02d65ee0ac30ad19.js, 20160921_5775da34d70f97a2d7aa3296f909af35.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "f85dba2504097034fa23d87391ecdaf7fe5f29824616a8d91d353284964bfac1"
    hash2       = "270e1d840937d10ac3eb1fdd04f0fbbbfd31a88a2f316c94c5167a23a2940644"

  strings:
    $s1 = "{return \"Tn\";})(),(function f000(){return \"GGn\";})(),(function f000(){return \"Um\";})(),(function f000(){return \"PTs\";})(" ascii
    $s2 = "rn \"PTs\";})(),(function f000(){return \"Tn\";})(),(function f000(){return \"Yi\";})(),(function f000(){return \"GGn\";})(),(fu" ascii
    $s3 = "ction f000(){return \"Ot\";})(),(function f000(){return \"Ot\";})(),(function f000(){return \"BIj\";})(),(function f000(){return" ascii
    $s4 = "n \"GGn\";})(),(function f000(){return \"IAa\";})(),(function f000(){return \"MJq\";})(),(function f000(){return \"Qz\";})(),(fu" ascii
    $s5 = "ion f000(){return \"Tn\";})(),(function f000(){return \"Yi\";})(),(function f000(){return \"WIj\";})(),(function f000(){return " ascii
    $s6 = "})(),(function f000(){return \"ZFe\";})(),(function f000(){return \"TRc\";})(),(function f000(){return \"GGn\";})(),(function f0" ascii
    $s7 = "rn \"OUx\";})(),(function f000(){return \"Um\";})(),(function f000(){return \"Rh\";})(),(function f000(){return \"TKl\";})(),(fu" ascii

  condition:
    (uint16(0) == 0x2f0a and (all of them)
    ) or (all of them)
}