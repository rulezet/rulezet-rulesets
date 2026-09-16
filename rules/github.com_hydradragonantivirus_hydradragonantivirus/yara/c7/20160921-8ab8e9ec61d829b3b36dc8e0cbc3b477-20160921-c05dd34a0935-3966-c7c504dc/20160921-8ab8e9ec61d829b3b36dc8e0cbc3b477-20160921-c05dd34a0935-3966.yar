rule _20160921_8ab8e9ec61d829b3b36dc8e0cbc3b477_20160921_c05dd34a0935_3966 {
  meta:
    description = "datamaliciousorder - from files 20160921_8ab8e9ec61d829b3b36dc8e0cbc3b477.js, 20160921_c05dd34a09358454c56b9c248f1d0304.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "6302a5443fa0c0309aa33e24b90ed81d05258a2a800cda52321e903fc44e0494"
    hash2       = "e330ec83e6ac964ffd679e6589494a6108e1995f570c539dee7b1be30953f8a3"

  strings:
    $s1 = "return \"OUx\";})(),(function f000(){return \"Vu\";})(),(function f000(){return \"DYs\";})(),(function f000(){return \"Oe\";})()" ascii
    $s2 = "f000(){return \"ZGq\";})(),(function f000(){return \"YTp\";})(),(function f000(){return \"Lp\";})(),(function f000(){return \"TR" ascii
    $s3 = "(),(function f000(){return \"GGn\";})(),(function f000(){return \"ZGq\";})(),(function f000(){return \"PTs\";})(),(function f000" ascii
    $s4 = " \"Lp\";})(),(function f000(){return \"DIa\";})(),(function f000(){return \"Zj\";})(),(function f000(){return \"MMz\";})(),(func" ascii
    $s5 = "turn \"MDb\";})(),(function f000(){return \"GGn\";})(),(function f000(){return \"ZIi\";})(),(function f000(){return \"PTi\";})()" ascii
    $s6 = ")(),(function f000(){return \"Vu\";})(),(function f000(){return \"BQb\";})(),(function f000(){return \"Qj\";})(),(function f000(" ascii

  condition:
    (uint16(0) == 0x2f0a and (all of them)
    ) or (all of them)
}