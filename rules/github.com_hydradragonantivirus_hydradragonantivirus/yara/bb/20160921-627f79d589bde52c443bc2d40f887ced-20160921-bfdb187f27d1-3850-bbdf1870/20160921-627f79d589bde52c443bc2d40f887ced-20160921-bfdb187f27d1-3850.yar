rule _20160921_627f79d589bde52c443bc2d40f887ced_20160921_bfdb187f27d1_3850 {
  meta:
    description = "datamaliciousorder - from files 20160921_627f79d589bde52c443bc2d40f887ced.js, 20160921_bfdb187f27d136f64e05f0dcf2ee4914.js, 20160921_c779962dc8b38bbb280b695e631131fa.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "f23a9d984b71a422ca30ec7f94f4a4cb0a2303699dc80edbced4a4c608e370e4"
    hash2       = "cbf2173e7b067de6ce6bf189ba38c78f3f0d97a7e6685c0191e08885badfeb3e"
    hash3       = "cf3f9e3180d8fa16719dbea90d762850a1742512c7be6bc42325dc9e094add30"

  strings:
    $s1 = "ck(){return \"Vb\";})(),(function fuck(){return \"Jo\";})(),(function fuck(){return \"Hs\";})(),(function fuck(){return \"UOe\";" ascii
    $s2 = "(),(function fuck(){return \"YQt\";})(),(function fuck(){return \"Za\";})(),(function fuck(){return \"IPu\";})(),(function fuck(" ascii
    $s3 = "nction fuck(){return \"LGo\";})(),(function fuck(){return \"IRn\";})(),(function fuck(){return \"NKq\";})(),(function fuck(){ret" ascii
    $s4 = "ction fuck(){return \"Dc\";})(),(function fuck(){return \"Hs\";})(),(function fuck(){return \"IPu\";})(),(function fuck(){return" ascii
    $s5 = "ion fuck(){return \"MBg\";})(),(function fuck(){return \"Nm\";})(),(function fuck(){return \"Wo\";})(),(function fuck(){return " ascii
    $s6 = " \"Oh\";})(),(function fuck(){return \"Ug\";})(),(function fuck(){return \"KVh\";})(),(function fuck(){return \"Vb\";})(),(funct" ascii

  condition:
    (uint16(0) == 0x2f0a and (all of them)
    ) or (all of them)
}