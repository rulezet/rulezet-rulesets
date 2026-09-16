rule _20160921_e0f34764de4fcb908eef371ab4011f31_20160922_9d6af2734812_5722 {
  meta:
    description = "datamaliciousorder - from files 20160921_e0f34764de4fcb908eef371ab4011f31.js, 20160922_9d6af27348126e594fbe29c3cf568591.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "de457f8d789ffcd672900ad06037697526230f620a01d113732fa3683b1604b1"
    hash2       = "3634189c93f3a76e0a4df72e631f0715b4b71427c157ca5fe116252ca00f1d9b"

  strings:
    $s1 = "00(){return \"OUx\";})(),(function f000(){return \"RPt\";})(),(function f000(){return \"Vj\";})(),(function f000(){return \"ZFe" ascii
    $s2 = "unction f000(){return \"Qa\";})(),(function f000(){return \"Tn\";})(),(function f000(){return \"Tn\";})(),(function f000(){retur" ascii
    $s3 = "(),(function f000(){return \"WIj\";})(),(function f000(){return \"ZFe\";})(),(function f000(){return \"Zj\";})(),(function f000(" ascii
    $s4 = "})(),(function f000(){return \"PTi\";})(),(function f000(){return \"Qj\";})(),(function f000(){return \"ZFe\";})(),(function f00" ascii
    $s5 = "){return \"Kw\";})(),(function f000(){return \"OUx\";})(),(function f000(){return \"KXg\";})(),(function f000(){return \"ZFe\";}" ascii

  condition:
    (uint16(0) == 0x2f0a and (all of them)
    ) or (all of them)
}