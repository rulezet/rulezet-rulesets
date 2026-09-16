rule _20160921_05de6ed1bba9a99cad4c92bf9ce97005_20160921_5775da34d70f_2648 {
  meta:
    description = "datamaliciousorder - from files 20160921_05de6ed1bba9a99cad4c92bf9ce97005.js, 20160921_5775da34d70f97a2d7aa3296f909af35.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "cc9a1bb338cbe502eae2d8092d1b4369f9be8a107f4db340bf51a1640991e960"
    hash2       = "270e1d840937d10ac3eb1fdd04f0fbbbfd31a88a2f316c94c5167a23a2940644"

  strings:
    $s1 = "n f000(){return \"Vj\";})(),(function f000(){return \"DIa\";})(),(function f000(){return \"Do\";})(),(function f000(){return \"M" ascii
    $s2 = "})(),(function f000(){return \"Qz\";})(),(function f000(){return \"OUx\";})(),(function f000(){return \"MBb\";})(),(function f00" ascii
    $s3 = "00(){return \"OUx\";})(),(function f000(){return \"Um\";})(),(function f000(){return \"PTs\";})(),(function f000(){return \"Tn\"" ascii
    $s4 = "turn \"Lp\";})(),(function f000(){return \"Yz\";})(),(function f000(){return \"Vu\";})(),(function f000(){return \"TRc\";})(),(f" ascii
    $s5 = "(){return \"GGn\";})(),(function f000(){return \"Br\";})(),(function f000(){return \"Mc\";})(),(function f000(){return \"Yx\";})" ascii
    $s6 = "(function f000(){return \"Vj\";})(),(function f000(){return \"Qz\";})(),(function f000(){return \"TRc\";})(),(function f000(){re" ascii
    $s7 = "\"Vu\";})(),(function f000(){return \"TRc\";})(),(function f000(){return \"WIj\";})(),(function f000(){return \"KXg\";})(),(func" ascii

  condition:
    (uint16(0) == 0x2f0a and (all of them)
    ) or (all of them)
}