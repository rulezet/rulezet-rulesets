rule _20160921_44880573519212a90b7d910319fc31d8_20160921_a8b3df7e98e8_5061 {
  meta:
    description = "datamaliciousorder - from files 20160921_44880573519212a90b7d910319fc31d8.js, 20160921_a8b3df7e98e8a886568b517b6d357d72.js, 20160921_ac32e5db1761db7bcee12f6443e4be71.js, 20160921_b9eadd20f28216849138290cb6dac4de.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "8427ee610833efbf68884e3ec13c4357ae35e1aa0bf8ddc2ffe99b9a7f44fb40"
    hash2       = "0652be8fe8ee502a5c45d7c0d1b7f5ea93bd8633350801afbb4709b88afc93e2"
    hash3       = "c720e572402df240156cf5af93a10b135edc995ca3aaedbfe6a9673216f7c930"
    hash4       = "4859166acfe74b9a623acc55b045aff7a4c46e4f5c457bb304c5169c6e7fb4a9"

  strings:
    $s1 = "on fuck(){return \"Xg\";})(),(function fuck(){return \"Za\";})(),(function fuck(){return \"GJx\";})(),(function fuck(){return \"" ascii
    $s2 = "w\";})(),(function fuck(){return \"MOj\";})(),(function fuck(){return \"GNm\";})(),(function fuck(){return \"Bz\";})(),(function" ascii
    $s3 = "unction fuck(){return \"KVh\";})(),(function fuck(){return \"UOe\";})(),(function fuck(){return \"Jo\";})(),(function fuck(){ret" ascii
    $s4 = "){return \"Mw\";})(),(function fuck(){return \"Yk\";})(),(function fuck(){return \"Mw\";})(),(function fuck(){return \"Jh\";})()" ascii
    $s5 = "),(function fuck(){return \"Ar\";})(),(function fuck(){return \"Xg\";})(),(function fuck(){return \"OQr\";})(),(function fuck(){" ascii

  condition:
    (uint16(0) == 0x2f0a and (all of them)
    ) or (all of them)
}