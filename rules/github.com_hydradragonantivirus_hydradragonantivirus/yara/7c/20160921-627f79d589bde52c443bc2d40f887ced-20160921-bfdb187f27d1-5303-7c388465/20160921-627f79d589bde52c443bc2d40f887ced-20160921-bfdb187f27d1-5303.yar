rule _20160921_627f79d589bde52c443bc2d40f887ced_20160921_bfdb187f27d1_5303 {
  meta:
    description = "datamaliciousorder - from files 20160921_627f79d589bde52c443bc2d40f887ced.js, 20160921_bfdb187f27d136f64e05f0dcf2ee4914.js, 20160921_c779962dc8b38bbb280b695e631131fa.js, 20160921_cb95437e5f7b0cd43bdbd6381ee6a105.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "f23a9d984b71a422ca30ec7f94f4a4cb0a2303699dc80edbced4a4c608e370e4"
    hash2       = "cbf2173e7b067de6ce6bf189ba38c78f3f0d97a7e6685c0191e08885badfeb3e"
    hash3       = "cf3f9e3180d8fa16719dbea90d762850a1742512c7be6bc42325dc9e094add30"
    hash4       = "46d771acb80357bcbb0857af9e7a4a35304fdbbf9785ec02f88f92f1268dfa71"

  strings:
    $s1 = "){return \"DRx\";})(),(function fuck(){return \"IPu\";})(),(function fuck(){return \"ZWu\";})(),(function fuck(){return \"Dc\";}" ascii
    $s2 = "{return \"Za\";})(),(function fuck(){return \"IPu\";})(),(function fuck(){return \"ZWu\";})(),(function fuck(){return \"Sx\";})(" ascii
    $s3 = "\"SUi\";})(),(function fuck(){return \"UOe\";})(),(function fuck(){return \"IPu\";})(),(function fuck(){return \"DRx\";})(),(fun" ascii
    $s4 = "\"RAi\";})(),(function fuck(){return \"RAi\";})(),(function fuck(){return \"OPz\";})(),(function fuck(){return \"IPu\";})(),(fun" ascii
    $s5 = "uck(){return \"Np\";})(),(function fuck(){return \"UOe\";})(),(function fuck(){return \"RAi\";})(),(function fuck(){return \"OPz" ascii

  condition:
    (uint16(0) == 0x2f0a and (all of them)
    ) or (all of them)
}