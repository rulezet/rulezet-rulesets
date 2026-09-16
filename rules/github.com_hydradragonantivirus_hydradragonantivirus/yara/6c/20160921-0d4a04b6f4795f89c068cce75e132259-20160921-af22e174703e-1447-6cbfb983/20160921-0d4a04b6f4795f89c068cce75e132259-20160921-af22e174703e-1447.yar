rule _20160921_0d4a04b6f4795f89c068cce75e132259_20160921_af22e174703e_1447 {
  meta:
    description = "datamaliciousorder - from files 20160921_0d4a04b6f4795f89c068cce75e132259.js, 20160921_af22e174703ebae0fa1368fd471dba37.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "e80f63f8ef5a9b52f119cc58d120fd7d74784d15d23ddc339948cb92383c800c"
    hash2       = "24c1540f49c4fe83a182058f70751619567afa9e8884c1dee7ae13e5fad14a59"

  strings:
    $s1  = "on fuck(){return \"UXf\";})(),(function fuck(){return \"DAa\";})(),(function fuck(){return \"TTs\";})(),(function fuck(){return " ascii
    $s2  = "k(){return \"CTm\";})(),(function fuck(){return \"Qh\";})(),(function fuck(){return \"DWe\";})(),(function fuck(){return \"Dc\";" ascii
    $s3  = "ion fuck(){return \"Yk\";})(),(function fuck(){return \"GJx\";})(),(function fuck(){return \"ZVi\";})(),(function fuck(){return " ascii
    $s4  = "nction fuck(){return \"Bz\";})(),(function fuck(){return \"CTm\";})(),(function fuck(){return \"Ve\";})(),(function fuck(){retur" ascii
    $s5  = "rn \"Ik\";})(),(function fuck(){return \"Hs\";})(),(function fuck(){return \"IRn\";})(),(function fuck(){return \"OQr\";})(),(fu" ascii
    $s6  = "return \"DWe\";})(),(function fuck(){return \"Dc\";})(),(function fuck(){return \"LGo\";})(),(function fuck(){return \"TTs\";})(" ascii
    $s7  = "\";})(),(function fuck(){return \"LGo\";})(),(function fuck(){return \"MBg\";})(),(function fuck(){return \"Qh\";})(),(function " ascii
    $s8  = "n fuck(){return \"CCb\";})(),(function fuck(){return \"EHo\";})(),(function fuck(){return \"IPu\";})(),(function fuck(){return " ascii
    $s9  = "urn \"Xw\";})(),(function fuck(){return \"MOj\";})(),(function fuck(){return \"NKq\";})(),(function fuck(){return \"GNm\";})(),(" ascii
    $s10 = "})(),(function fuck(){return \"XFd\";})(),(function fuck(){return \"Wo0\";})(),(function fuck(){return \"Jo\";})(),(function fuc" ascii
    $s11 = "(){return \"IPu\";})(),(function fuck(){return \"Ve\";})(),(function fuck(){return \"UXf\";})(),(function fuck(){return \"LGo\";" ascii
    $s12 = ")(),(function fuck(){return \"IPu\";})(),(function fuck(){return \"Ug\";})(),(function fuck(){return \"Zy\";})(),(function fuck(" ascii
    $s13 = "{return \"GNm\";})(),(function fuck(){return \"Bz\";})()];" fullword ascii

  condition:
    (uint16(0) == 0x2f0a and (8 of them)
    ) or (all of them)
}