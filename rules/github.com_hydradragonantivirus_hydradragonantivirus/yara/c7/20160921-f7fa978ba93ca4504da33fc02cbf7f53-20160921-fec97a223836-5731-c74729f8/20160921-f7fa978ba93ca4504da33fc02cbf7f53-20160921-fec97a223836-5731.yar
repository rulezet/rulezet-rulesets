rule _20160921_f7fa978ba93ca4504da33fc02cbf7f53_20160921_fec97a223836_5731 {
  meta:
    description = "datamaliciousorder - from files 20160921_f7fa978ba93ca4504da33fc02cbf7f53.js, 20160921_fec97a223836973c5d09ac6d41b2ad43.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "8c8d20603b0870465254e9f226f52f020b5b1d986c61571e7a3097b32ea728e0"
    hash2       = "d8c26b92e119ca52cb4c0aa43351cde4400c3d6abac819e57a391628e14280cb"

  strings:
    $s1 = "ion fuck(){return \"Nm\";})(),(function fuck(){return \"FJs\";})(),(function fuck(){return \"Np\";})(),(function fuck(){return " ascii
    $s2 = "unction fuck(){return \"Qh\";})(),(function fuck(){return \"ZWu\";})(),(function fuck(){return \"GWo\";})(),(function fuck(){ret" ascii
    $s3 = "k(){return \"AUx\";})(),(function fuck(){return \"RAi\";})(),(function fuck(){return \"RAi\";})(),(function fuck(){return \"ADy" ascii
    $s4 = "(){return \"IRn\";})(),(function fuck(){return \"MBg\";})(),(function fuck(){return \"IKv\";})(),(function fuck(){return \"AUx\"" ascii
    $s5 = "Go\";})(),(function fuck(){return \"YQt\";})(),(function fuck(){return \"UOe\";})(),(function fuck(){return \"NKq\";})(),(functi" ascii

  condition:
    (uint16(0) == 0x2f0a and (all of them)
    ) or (all of them)
}