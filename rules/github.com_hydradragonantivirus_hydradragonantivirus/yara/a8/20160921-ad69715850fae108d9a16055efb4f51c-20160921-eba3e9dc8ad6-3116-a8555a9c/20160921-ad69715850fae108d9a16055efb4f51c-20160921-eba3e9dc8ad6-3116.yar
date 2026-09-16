rule _20160921_ad69715850fae108d9a16055efb4f51c_20160921_eba3e9dc8ad6_3116 {
  meta:
    description = "datamaliciousorder - from files 20160921_ad69715850fae108d9a16055efb4f51c.js, 20160921_eba3e9dc8ad614a7e5c422a93cd7b424.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "76ed8c5c3ace4ce119f1561d5d61ca2e454da79e9156a8397e72d6eed3a22d74"
    hash2       = "f0f6c6f4fe3daf7aae3b8d7276adbcc6577a8bf844eeae945023523b63b6cc9a"

  strings:
    $s1 = " f000(){return \"KDh\";})(),(function f000(){return \"PTi\";})(),(function f000(){return \"NBs\";})(),(function f000(){return \"" ascii
    $s2 = "})(),(function f000(){return \"Yi\";})(),(function f000(){return \"WIj\";})(),(function f000(){return \"Wb\";})(),(function f000" ascii
    $s3 = "n \"Sj\";})(),(function f000(){return \"Lp\";})(),(function f000(){return \"Tn\";})(),(function f000(){return \"TRc\";})(),(func" ascii
    $s4 = "n \"Wb\";})(),(function f000(){return \"TRc\";})(),(function f000(){return \"WIj\";})(),(function f000(){return \"Vu\";})(),(fun" ascii
    $s5 = "f000(){return \"GGn\";})(),(function f000(){return \"XTn\";})(),(function f000(){return \"Qz\";})(),(function f000(){return \"Wb" ascii
    $s6 = "n \"ZGq\";})(),(function f000(){return \"HJm\";})(),(function f000(){return \"Oh\";})(),(function f000(){return \"GGn\";})(),(fu" ascii
    $s7 = "rn \"Zj\";})(),(function f000(){return \"GGn\";})(),(function f000(){return \"Nv\";})(),(function f000(){return \"IAa\";})(),(fu" ascii

  condition:
    (uint16(0) == 0x2f0a and (all of them)
    ) or (all of them)
}