rule _20160921_18e4d81197d615e3008ec96ea25b7dc4_20160921_daba59e7a6b9_4547 {
  meta:
    description = "datamaliciousorder - from files 20160921_18e4d81197d615e3008ec96ea25b7dc4.js, 20160921_daba59e7a6b9ed6983cd2cbef1eb1597.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "4b707313cf8ee2fdf903e5516937a17e48e75059c21a08483659705a96da9670"
    hash2       = "94c619539e853fdec1958270da7516c52bbcf442ee9ca0569d11e19e70ae29eb"

  strings:
    $s1 = "000(){return \"DNa\";})(),(function f000(){return \"Qj\";})(),(function f000(){return \"Zj\";})(),(function f000(){return \"Do\"" ascii
    $s2 = "n f000(){return \"SEo\";})(),(function f000(){return \"RVb\";})(),(function f000(){return \"Yi\";})(),(function f000(){return \"" ascii
    $s3 = "(function f000(){return \"BMj\";})(),(function f000(){return \"DNa\";})(),(function f000(){return \"GGn\";})(),(function f000(){" ascii
    $s4 = "00(){return \"PTs\";})(),(function f000(){return \"TRc\";})(),(function f000(){return \"WIj\";})(),(function f000(){return \"RPt" ascii
    $s5 = "0(){return \"PTs\";})(),(function f000(){return \"GGn\";})(),(function f000(){return \"MDb\";})(),(function f000(){return \"GGn" ascii

  condition:
    (uint16(0) == 0x2f0a and (all of them)
    ) or (all of them)
}