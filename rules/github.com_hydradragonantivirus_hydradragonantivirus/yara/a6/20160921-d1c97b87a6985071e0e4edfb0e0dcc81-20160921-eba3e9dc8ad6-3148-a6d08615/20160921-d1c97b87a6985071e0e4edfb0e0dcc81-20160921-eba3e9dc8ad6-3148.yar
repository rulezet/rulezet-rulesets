rule _20160921_d1c97b87a6985071e0e4edfb0e0dcc81_20160921_eba3e9dc8ad6_3148 {
  meta:
    description = "datamaliciousorder - from files 20160921_d1c97b87a6985071e0e4edfb0e0dcc81.js, 20160921_eba3e9dc8ad614a7e5c422a93cd7b424.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "b5d1f1d63107b329353fe8130c80608d28a9b1ed12f81c240129d04be6842bf0"
    hash2       = "f0f6c6f4fe3daf7aae3b8d7276adbcc6577a8bf844eeae945023523b63b6cc9a"

  strings:
    $s1 = "(function f000(){return \"Vu\";})(),(function f000(){return \"RPt\";})(),(function f000(){return \"TRc\";})(),(function f000(){r" ascii
    $s2 = "unction f000(){return \"GGn\";})(),(function f000(){return \"Go\";})(),(function f000(){return \"PTi\";})(),(function f000(){ret" ascii
    $s3 = "(function f000(){return \"KXg\";})(),(function f000(){return \"Wb\";})(),(function f000(){return \"Vu\";})(),(function f000(){re" ascii
    $s4 = "q\";})(),(function f000(){return \"Wb\";})(),(function f000(){return \"WIj\";})(),(function f000(){return \"Uo\";})(),(function " ascii
    $s5 = "rn \"Qz\";})(),(function f000(){return \"Vj\";})(),(function f000(){return \"TRc\";})(),(function f000(){return \"WIj\";})(),(fu" ascii
    $s6 = "return \"GGn\";})(),(function f000(){return \"DNa\";})(),(function f000(){return \"Sj\";})(),(function f000(){return \"UEg\";})(" ascii
    $s7 = "eturn \"Yi\";})(),(function f000(){return \"OUx\";})(),(function f000(){return \"ZGq\";})(),(function f000(){return \"HJm\";})()" ascii

  condition:
    (uint16(0) == 0x2f0a and (all of them)
    ) or (all of them)
}