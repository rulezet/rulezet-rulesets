rule _20160921_702e8529103b960a902ddb030da0de45_20160922_f0d656e55be0_3041 {
  meta:
    description = "datamaliciousorder - from files 20160921_702e8529103b960a902ddb030da0de45.js, 20160922_f0d656e55be0c93b2b5e1f0eda45da9a.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "cf8ba9fdbe4ef225cb892f7294538710b1dd7e8bc4e280897680c51e03816d1c"
    hash2       = "276c24e399a13bf7907294578800d75620fb48bcd34bc84b9d92448375c72d37"

  strings:
    $s1 = "ion f000(){return \"Sq\";})(),(function f000(){return \"Lp\";})(),(function f000(){return \"MDb\";})(),(function f000(){return " ascii
    $s2 = "return \"PTs\";})(),(function f000(){return \"SGs\";})(),(function f000(){return \"MDb\";})(),(function f000(){return \"Vj\";})(" ascii
    $s3 = "j\";})(),(function f000(){return \"Rh\";})(),(function f000(){return \"MDb\";})(),(function f000(){return \"Sv\";})(),(function " ascii
    $s4 = "(),(function f000(){return \"IAa\";})(),(function f000(){return \"Oe\";})(),(function f000(){return \"OMd\";})(),(function f000(" ascii
    $s5 = "00(){return \"Vu\";})(),(function f000(){return \"YTp\";})(),(function f000(){return \"MDb\";})(),(function f000(){return \"HJm" ascii
    $s6 = "f000(){return \"Qz\";})(),(function f000(){return \"MDb\";})(),(function f000(){return \"DAp\";})(),(function f000(){return \"Iq" ascii
    $s7 = "function f000(){return \"Mt\";})(),(function f000(){return \"Do\";})(),(function f000(){return \"MDb\";})(),(function f000(){ret" ascii

  condition:
    (uint16(0) == 0x2f0a and (all of them)
    ) or (all of them)
}