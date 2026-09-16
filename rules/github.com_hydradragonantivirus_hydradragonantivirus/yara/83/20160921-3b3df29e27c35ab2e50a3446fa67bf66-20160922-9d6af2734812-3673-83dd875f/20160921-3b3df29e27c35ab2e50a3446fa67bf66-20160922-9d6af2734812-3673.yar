rule _20160921_3b3df29e27c35ab2e50a3446fa67bf66_20160922_9d6af2734812_3673 {
  meta:
    description = "datamaliciousorder - from files 20160921_3b3df29e27c35ab2e50a3446fa67bf66.js, 20160922_9d6af27348126e594fbe29c3cf568591.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "dd15d322a8169ff9edb922ead245c93109f14c5fa4f31811eb58601888323ad2"
    hash2       = "3634189c93f3a76e0a4df72e631f0715b4b71427c157ca5fe116252ca00f1d9b"

  strings:
    $s1 = "(function f000(){return \"Go\";})(),(function f000(){return \"Um\";})(),(function f000(){return \"BMj\";})(),(function f000(){re" ascii
    $s2 = ",(function f000(){return \"Vj\";})(),(function f000(){return \"Br\";})(),(function f000(){return \"GGn\";})(),(function f000(){r" ascii
    $s3 = "GGn\";})(),(function f000(){return \"Sv\";})(),(function f000(){return \"DYx\";})(),(function f000(){return \"GGn\";})(),(functi" ascii
    $s4 = "rn \"Qp\";})(),(function f000(){return \"GGn\";})(),(function f000(){return \"Wb\";})(),(function f000(){return \"Nv\";})(),(fun" ascii
    $s5 = ")(),(function f000(){return \"BMj\";})(),(function f000(){return \"Vj\";})(),(function f000(){return \"GGn\";})(),(function f000" ascii
    $s6 = ",(function f000(){return \"Yi\";})(),(function f000(){return \"Vj\";})(),(function f000(){return \"TRc\";})(),(function f000(){r" ascii

  condition:
    (uint16(0) == 0x2f0a and (all of them)
    ) or (all of them)
}