rule _20160921_6d18600f3019656b0ab414a3d1a69ddb_20160921_eba3e9dc8ad6_1123 {
  meta:
    description = "datamaliciousorder - from files 20160921_6d18600f3019656b0ab414a3d1a69ddb.js, 20160921_eba3e9dc8ad614a7e5c422a93cd7b424.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "fb0471dc4828588d37d01ddaa7b9454e82acacc4dfdd9f0998b461661e3810db"
    hash2       = "f0f6c6f4fe3daf7aae3b8d7276adbcc6577a8bf844eeae945023523b63b6cc9a"

  strings:
    $s1  = "){return \"Wb\";})(),(function f000(){return \"Vu\";})(),(function f000(){return \"TRc\";})(),(function f000(){return \"WIj\";})" ascii
    $s2  = "){return \"MJq\";})(),(function f000(){return \"TKl\";})(),(function f000(){return \"MDb\";})(),(function f000(){return \"Um\";}" ascii
    $s3  = ")(),(function f000(){return \"RPt\";})(),(function f000(){return \"Wb\";})(),(function f000(){return \"KXg\";})(),(function f000" ascii
    $s4  = "\"TKl\";})(),(function f000(){return \"Vj\";})(),(function f000(){return \"Zj\";})(),(function f000(){return \"Do\";})(),(functi" ascii
    $s5  = "ction f000(){return \"PTs\";})(),(function f000(){return \"Mc\";})(),(function f000(){return \"GGn\";})(),(function f000(){retur" ascii
    $s6  = "turn \"PTi\";})(),(function f000(){return \"NBs\";})(),(function f000(){return \"Yi\";})(),(function f000(){return \"WIj\";})()," ascii
    $s7  = "{return \"GGn\";})(),(function f000(){return \"Go\";})(),(function f000(){return \"Um\";})(),(function f000(){return \"Oh\";})()" ascii
    $s8  = "tion f000(){return \"Yv\";})(),(function f000(){return \"Qa\";})(),(function f000(){return \"DYx\";})(),(function f000(){return " ascii
    $s9  = ",(function f000(){return \"OUx\";})(),(function f000(){return \"Wb\";})(),(function f000(){return \"TRc\";})(),(function f000(){" ascii
    $s10 = "Qa\";})(),(function f000(){return \"Qj\";})(),(function f000(){return \"MDb\";})(),(function f000(){return \"EZu\";})(),(functio" ascii
    $s11 = "(function f000(){return \"Qj\";})(),(function f000(){return \"MDb\";})(),(function f000(){return \"Nv\";})(),(function f000(){re" ascii
    $s12 = "p\";})(),(function f000(){return \"Vu\";})(),(function f000(){return \"GGn\";})(),(function f000(){return \"MDb\";})(),(function" ascii
    $s13 = "GGn\";})(),(function f000(){return \"GGn\";})(),(function f000(){return \"Tb\";})(),(function f000(){return \"SEo\";})(),(functi" ascii
    $s14 = "{return \"SEo\";})(),(function f000(){return \"NYh\";})(),(function f000(){return \"Wb\";})(),(function f000(){return \"GGn\";})" ascii
    $s15 = "0(){return \"GGn\";})(),(function f000(){return \"Qp\";})(),(function f000(){return \"GGn\";})(),(function f000(){return \"Qa\";" ascii
    $s16 = "f000(){return \"Wb\";})(),(function f000(){return \"TRc\";})(),(function f000(){return \"QDg\";})(),(function f000(){return \"Sv" ascii
    $s17 = ")(),(function f000(){return \"Sq\";})(),(function f000(){return \"Vj\";})(),(function f000(){return \"GGn\";})(),(function f000(" ascii

  condition:
    (uint16(0) == 0x2f0a and (8 of them)
    ) or (all of them)
}