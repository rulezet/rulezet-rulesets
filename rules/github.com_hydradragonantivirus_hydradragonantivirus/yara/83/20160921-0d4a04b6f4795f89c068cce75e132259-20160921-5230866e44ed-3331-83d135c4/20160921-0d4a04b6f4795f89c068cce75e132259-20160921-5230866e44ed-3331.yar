rule _20160921_0d4a04b6f4795f89c068cce75e132259_20160921_5230866e44ed_3331 {
  meta:
    description = "datamaliciousorder - from files 20160921_0d4a04b6f4795f89c068cce75e132259.js, 20160921_5230866e44eda4e054d929933fdfdae1.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "e80f63f8ef5a9b52f119cc58d120fd7d74784d15d23ddc339948cb92383c800c"
    hash2       = "4b11d10d6c2a935fa29f47c13ee54d426aac8d667f3bc2f79681ac7e4d365c76"

  strings:
    $s1 = "Ux\";})(),(function fuck(){return \"MUs\";})(),(function fuck(){return \"MBg\";})(),(function fuck(){return \"CCb\";})(),(functi" ascii
    $s2 = ",(function fuck(){return \"Dc\";})(),(function fuck(){return \"OQr\";})(),(function fuck(){return \"Yk\";})(),(function fuck(){r" ascii
    $s3 = "n fuck(){return \"AUx\";})(),(function fuck(){return \"MUs\";})(),(function fuck(){return \"LGo\";})(),(function fuck(){return " ascii
    $s4 = "{return \"Vb\";})(),(function fuck(){return \"ZVi\";})(),(function fuck(){return \"Xw\";})(),(function fuck(){return \"IPu\";})(" ascii
    $s5 = "\"USf\";})(),(function fuck(){return \"TTs\";})(),(function fuck(){return \"AUx\";})(),(function fuck(){return \"Ug\";})(),(func" ascii
    $s6 = "\"SUi\";})(),(function fuck(){return \"Jo\";})(),(function fuck(){return \"MOj\";})(),(function fuck(){return \"GNm\";})(),(func" ascii

  condition:
    (uint16(0) == 0x2f0a and (all of them)
    ) or (all of them)
}