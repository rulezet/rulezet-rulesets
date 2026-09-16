rule _20160921_be923844637026740bc9e5a4aad21ebe_20160921_ea3000546b29_971 {
  meta:
    description = "datamaliciousorder - from files 20160921_be923844637026740bc9e5a4aad21ebe.js, 20160921_ea3000546b29aee563be9d58318d1857.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "f50e7368497d3ab714aae3798280c1b53ff9f91f0081f1eafa0b9e23e4928336"
    hash2       = "eb46ac22bc2e86a5bacf6fbfffe3a746600369a5d28c84d095b1269bcdfe9cc6"

  strings:
    $s1  = " f000(){return \"Br\";})(),(function f000(){return \"IPu\";})(),(function f000(){return \"Wy\";})(),(function f000(){return \"Br" ascii
    $s2  = "unction f000(){return \"QDg\";})(),(function f000(){return \"ZIi\";})(),(function f000(){return \"Rh\";})(),(function f000(){ret" ascii
    $s3  = "return \"Sq\";})(),(function f000(){return \"TKl\";})(),(function f000(){return \"OUx\";})(),(function f000(){return \"Qa\";})()" ascii
    $s4  = "return \"Sq\";})(),(function f000(){return \"Br\";})(),(function f000(){return \"GGn\";})(),(function f000(){return \"MDb\";})()" ascii
    $s5  = "f000(){return \"MJq\";})(),(function f000(){return \"XTn\";})(),(function f000(){return \"GGn\";})(),(function f000(){return \"W" ascii
    $s6  = "000(){return \"GGn\";})(),(function f000(){return \"KDh\";})(),(function f000(){return \"Nv\";})(),(function f000(){return \"BMj" ascii
    $s7  = "n\";})(),(function f000(){return \"KDh\";})(),(function f000(){return \"DYx\";})(),(function f000(){return \"GGn\";})(),(functio" ascii
    $s8  = "(),(function f000(){return \"GGn\";})(),(function f000(){return \"Oh\";})(),(function f000(){return \"DYx\";})(),(function f000(" ascii
    $s9  = "00(){return \"Tn\";})(),(function f000(){return \"XTn\";})(),(function f000(){return \"GGn\";})(),(function f000(){return \"WIj" ascii
    $s10 = "t\";})(),(function f000(){return \"KXg\";})(),(function f000(){return \"RPt\";})(),(function f000(){return \"Qj\";})(),(function" ascii
    $s11 = "n \"Tn\";})(),(function f000(){return \"GGn\";})(),(function f000(){return \"Qa\";})(),(function f000(){return \"HJm\";})(),(fun" ascii
    $s12 = "0(){return \"Tn\";})(),(function f000(){return \"GGn\";})(),(function f000(){return \"ZIi\";})(),(function f000(){return \"Rh\";" ascii
    $s13 = " f000(){return \"Tn\";})(),(function f000(){return \"GGn\";})(),(function f000(){return \"ZGq\";})(),(function f000(){return \"Z" ascii
    $s14 = "\"Yv\";})(),(function f000(){return \"UEg\";})(),(function f000(){return \"GGn\";})(),(function f000(){return \"WIj\";})(),(func" ascii
    $s15 = "tion f000(){return \"Tn\";})(),(function f000(){return \"GGn\";})(),(function f000(){return \"SEo\";})(),(function f000(){return" ascii
    $s16 = "00(){return \"ZGq\";})(),(function f000(){return \"Wb\";})(),(function f000(){return \"Do\";})(),(function f000(){return \"WIj\"" ascii
    $s17 = "){return \"Tn\";})(),(function f000(){return \"GGn\";})(),(function f000(){return \"DYs\";})(),(function f000(){return \"IPu\";}" ascii
    $s18 = "tion f000(){return \"GGn\";})(),(function f000(){return \"Oh\";})(),(function f000(){return \"Qa\";})(),(function f000(){return " ascii
    $s19 = ")(),(function f000(){return \"SEo\";})(),(function f000(){return \"Tn\";})(),(function f000(){return \"GGn\";})(),(function f000" ascii
    $s20 = "q\";})(),(function f000(){return \"WIj\";})(),(function f000(){return \"Vu\";})(),(function f000(){return \"Tb\";})(),(function " ascii

  condition:
    (uint16(0) == 0x2f0a and (8 of them)
    ) or (all of them)
}