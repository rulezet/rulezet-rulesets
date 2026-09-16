rule _20160921_5e78b76ea160d891abcb41db9983d51f_20160921_a8b3df7e98e8_5263 {
  meta:
    description = "datamaliciousorder - from files 20160921_5e78b76ea160d891abcb41db9983d51f.js, 20160921_a8b3df7e98e8a886568b517b6d357d72.js, 20160921_ac32e5db1761db7bcee12f6443e4be71.js, 20160921_b9eadd20f28216849138290cb6dac4de.js, 20160921_eda7773555acd8e0be7f4e8bf6d0b010.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "789149d5f226f5eb3642909acb465b5f94d946ee53a79d693b40f83359c4471f"
    hash2       = "0652be8fe8ee502a5c45d7c0d1b7f5ea93bd8633350801afbb4709b88afc93e2"
    hash3       = "c720e572402df240156cf5af93a10b135edc995ca3aaedbfe6a9673216f7c930"
    hash4       = "4859166acfe74b9a623acc55b045aff7a4c46e4f5c457bb304c5169c6e7fb4a9"
    hash5       = "af4e0a7c109ffa140c9db57a44bcd9c5d9b5a7c75daded0b422d2cec24c01c8b"

  strings:
    $s1 = "n \"ZLd\";})(),(function fuck(){return \"Ve\";})(),(function fuck(){return \"Av\";})(),(function fuck(){return \"Np\";})(),(func" ascii
    $s2 = "y\";})(),(function fuck(){return \"LGo\";})(),(function fuck(){return \"UOe\";})(),(function fuck(){return \"NKq\";})(),(functio" ascii
    $s3 = "ck(){return \"TTs\";})(),(function fuck(){return \"LGo\";})(),(function fuck(){return \"RAi\";})(),(function fuck(){return \"USf" ascii
    $s4 = ";})(),(function fuck(){return \"Np\";})(),(function fuck(){return \"Hs\";})(),(function fuck(){return \"IPu\";})(),(function fuc" ascii
    $s5 = "ction fuck(){return \"DRx\";})(),(function fuck(){return \"IPu\";})(),(function fuck(){return \"LGo\";})(),(function fuck(){retu" ascii

  condition:
    (uint16(0) == 0x2f0a and (all of them)
    ) or (all of them)
}