rule _20160921_527d7c3756974f804734da343b6b6f0e_20160921_eba3e9dc8ad6_5173 {
  meta:
    description = "datamaliciousorder - from files 20160921_527d7c3756974f804734da343b6b6f0e.js, 20160921_eba3e9dc8ad614a7e5c422a93cd7b424.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "7d2dd725d314277b3b7cf1c94ae8894dce1d36430ff22819c2fecb47f14c3f43"
    hash2       = "f0f6c6f4fe3daf7aae3b8d7276adbcc6577a8bf844eeae945023523b63b6cc9a"

  strings:
    $s1 = "f000(){return \"PTs\";})(),(function f000(){return \"Tn\";})(),(function f000(){return \"Yi\";})(),(function f000(){return \"WIj" ascii
    $s2 = "{return \"GGn\";})(),(function f000(){return \"KXg\";})(),(function f000(){return \"Vu\";})(),(function f000(){return \"Vj\";})(" ascii
    $s3 = "ction f000(){return \"XTn\";})(),(function f000(){return \"Vj\";})(),(function f000(){return \"Zj\";})(),(function f000(){return" ascii
    $s4 = "){return \"KXg\";})(),(function f000(){return \"Vu\";})(),(function f000(){return \"Zj\";})(),(function f000(){return \"Do\";})(" ascii
    $s5 = "\";})(),(function f000(){return \"GGn\";})(),(function f000(){return \"DYs\";})(),(function f000(){return \"Lp\";})(),(function " ascii

  condition:
    (uint16(0) == 0x2f0a and (all of them)
    ) or (all of them)
}