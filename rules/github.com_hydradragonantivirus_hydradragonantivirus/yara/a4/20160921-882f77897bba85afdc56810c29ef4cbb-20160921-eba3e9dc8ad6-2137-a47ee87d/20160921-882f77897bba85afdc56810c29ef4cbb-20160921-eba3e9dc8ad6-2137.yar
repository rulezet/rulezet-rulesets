rule _20160921_882f77897bba85afdc56810c29ef4cbb_20160921_eba3e9dc8ad6_2137 {
  meta:
    description = "datamaliciousorder - from files 20160921_882f77897bba85afdc56810c29ef4cbb.js, 20160921_eba3e9dc8ad614a7e5c422a93cd7b424.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "9e1a86c6dc71a5b10659658c07a01bb1541887750ecf88ab56997c7dbc2d180c"
    hash2       = "f0f6c6f4fe3daf7aae3b8d7276adbcc6577a8bf844eeae945023523b63b6cc9a"

  strings:
    $s1 = "unction f000(){return \"KDh\";})(),(function f000(){return \"MBb\";})(),(function f000(){return \"Oh\";})(),(function f000(){ret" ascii
    $s2 = "unction f000(){return \"MMz\";})(),(function f000(){return \"TKp\";})(),(function f000(){return \"Vj\";})(),(function f000(){ret" ascii
    $s3 = "return \"Tn\";})(),(function f000(){return \"GGn\";})(),(function f000(){return \"EZu\";})(),(function f000(){return \"DYx\";})(" ascii
    $s4 = "),(function f000(){return \"GGn\";})(),(function f000(){return \"EZu\";})(),(function f000(){return \"MBb\";})(),(function f000(" ascii
    $s5 = "Dh\";})(),(function f000(){return \"Um\";})(),(function f000(){return \"SGs\";})(),(function f000(){return \"DIa\";})(),(functio" ascii
    $s6 = "Xg\";})(),(function f000(){return \"RPt\";})(),(function f000(){return \"Kw\";})(),(function f000(){return \"Zj\";})(),(function" ascii
    $s7 = ")(),(function f000(){return \"MMz\";})(),(function f000(){return \"TKp\";})(),(function f000(){return \"Vj\";})(),(function f000" ascii
    $s8 = "unction f000(){return \"Vu\";})(),(function f000(){return \"TRc\";})(),(function f000(){return \"WIj\";})(),(function f000(){ret" ascii
    $s9 = "000(){return \"Lp\";})(),(function f000(){return \"Sq\";})(),(function f000(){return \"Yi\";})(),(function f000(){return \"GGn\"" ascii

  condition:
    (uint16(0) == 0x2f0a and (all of them)
    ) or (all of them)
}