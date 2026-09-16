rule _20160921_37aa38f76e02afb64903280105ce4597_20160921_eba3e9dc8ad6_4914 {
  meta:
    description = "datamaliciousorder - from files 20160921_37aa38f76e02afb64903280105ce4597.js, 20160921_eba3e9dc8ad614a7e5c422a93cd7b424.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "768a32c669c193375bb8e7adb97cdbb697cd6f4f09fb5dc67bb63e62b7de29cf"
    hash2       = "f0f6c6f4fe3daf7aae3b8d7276adbcc6577a8bf844eeae945023523b63b6cc9a"

  strings:
    $s1 = "){return \"GGn\";})(),(function f000(){return \"Qa\";})(),(function f000(){return \"Nv\";})(),(function f000(){return \"Rh\";})(" ascii
    $s2 = " \"KXg\";})(),(function f000(){return \"Vj\";})(),(function f000(){return \"Vu\";})(),(function f000(){return \"Zj\";})(),(funct" ascii
    $s3 = "tion f000(){return \"Vu\";})(),(function f000(){return \"Kw\";})(),(function f000(){return \"TKl\";})(),(function f000(){return " ascii
    $s4 = "urn \"Qa\";})(),(function f000(){return \"Nv\";})(),(function f000(){return \"Rh\";})(),(function f000(){return \"Yi\";})(),(fun" ascii
    $s5 = "turn \"Wb\";})(),(function f000(){return \"Vj\";})(),(function f000(){return \"GGn\";})(),(function f000(){return \"MDb\";})(),(" ascii

  condition:
    (uint16(0) == 0x2f0a and (all of them)
    ) or (all of them)
}