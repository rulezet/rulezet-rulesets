rule _20160921_19d073f9fafc88c8b86047e72c80e9d8_20160921_b71168af39c5_2756 {
  meta:
    description = "datamaliciousorder - from files 20160921_19d073f9fafc88c8b86047e72c80e9d8.js, 20160921_b71168af39c5eec1d403d381eea7ffe1.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "9b03e3cbdce0a3374d427a6b76ef3eb59bc90337947054be78218aab4aa3a5f9"
    hash2       = "c8811edeb74999e8dd226f7fa9d7963ccfc998904ecb9474d036376253dc6fde"

  strings:
    $s1 = "(),(function f000(){return \"QDg\";})(),(function f000(){return \"Yv\";})(),(function f000(){return \"Nv\";})(),(function f000()" ascii
    $s2 = "\";})(),(function f000(){return \"Vj\";})(),(function f000(){return \"Rh\";})(),(function f000(){return \"GGn\";})(),(function f" ascii
    $s3 = "nction f000(){return \"Km\";})(),(function f000(){return \"Iq\";})(),(function f000(){return \"UEg\";})(),(function f000(){retur" ascii
    $s4 = "(){return \"DIa\";})(),(function f000(){return \"GGn\";})(),(function f000(){return \"BIj\";})(),(function f000(){return \"Wy\";" ascii
    $s5 = "{return \"Qz\";})(),(function f000(){return \"OUx\";})(),(function f000(){return \"MBb\";})(),(function f000(){return \"YTp\";})" ascii
    $s6 = "eturn \"GGn\";})(),(function f000(){return \"DYs\";})(),(function f000(){return \"Um\";})(),(function f000(){return \"Mt\";})()," ascii
    $s7 = "QDg\";})(),(function f000(){return \"Nv\";})(),(function f000(){return \"BQb\";})(),(function f000(){return \"DIa\";})(),(functi" ascii

  condition:
    (uint16(0) == 0x2f0a and (all of them)
    ) or (all of them)
}