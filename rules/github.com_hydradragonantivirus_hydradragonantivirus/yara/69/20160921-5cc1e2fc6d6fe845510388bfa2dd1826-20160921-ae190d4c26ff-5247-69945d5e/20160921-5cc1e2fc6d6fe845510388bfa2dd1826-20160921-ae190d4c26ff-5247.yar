rule _20160921_5cc1e2fc6d6fe845510388bfa2dd1826_20160921_ae190d4c26ff_5247 {
  meta:
    description = "datamaliciousorder - from files 20160921_5cc1e2fc6d6fe845510388bfa2dd1826.js, 20160921_ae190d4c26ff954cee57fde04839fdcd.js, 20160921_f7fa978ba93ca4504da33fc02cbf7f53.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "8517cbcc9f90e7835f4bbbef31cd3779f0298cca7076dd98e48fb69d359f4820"
    hash2       = "0a337ab3ebbd0c762482045ac2f2536c27fbe1276893efdedbafc2c805709064"
    hash3       = "8c8d20603b0870465254e9f226f52f020b5b1d986c61571e7a3097b32ea728e0"

  strings:
    $s1 = "unction fuck(){return \"DRx\";})(),(function fuck(){return \"IPu\";})(),(function fuck(){return \"Ai\";})(),(function fuck(){ret" ascii
    $s2 = "(){return \"Jo\";})(),(function fuck(){return \"XCr\";})(),(function fuck(){return \"MUs\";})(),(function fuck(){return \"USf\";" ascii
    $s3 = "n \"IOs\";})(),(function fuck(){return \"Fv\";})(),(function fuck(){return \"TTs\";})(),(function fuck(){return \"Ai\";})(),(fun" ascii
    $s4 = "t\";})(),(function fuck(){return \"IOs\";})(),(function fuck(){return \"IPu\";})(),(function fuck(){return \"DRx\";})(),(functio" ascii
    $s5 = "){return \"IPu\";})(),(function fuck(){return \"ZLd\";})(),(function fuck(){return \"EHo\";})(),(function fuck(){return \"UOe\";" ascii

  condition:
    (uint16(0) == 0x2f0a and (all of them)
    ) or (all of them)
}