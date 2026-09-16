rule _20160921_a210d5e93bf8b06dbd0a1b262abe210f_20160921_a8b3df7e98e8_1918 {
  meta:
    description = "datamaliciousorder - from files 20160921_a210d5e93bf8b06dbd0a1b262abe210f.js, 20160921_a8b3df7e98e8a886568b517b6d357d72.js, 20160921_ac32e5db1761db7bcee12f6443e4be71.js, 20160921_b9eadd20f28216849138290cb6dac4de.js, 20160921_dc73cfa7a33eb762f38614c69a95919d.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "681408ae198939a760d376554e62f86e9d1fe2306266ffaee496dc9eed4d0687"
    hash2       = "0652be8fe8ee502a5c45d7c0d1b7f5ea93bd8633350801afbb4709b88afc93e2"
    hash3       = "c720e572402df240156cf5af93a10b135edc995ca3aaedbfe6a9673216f7c930"
    hash4       = "4859166acfe74b9a623acc55b045aff7a4c46e4f5c457bb304c5169c6e7fb4a9"
    hash5       = "50e80269adbbca38f500219eaf7cec16f396b3d8a7c56d342b2e4839819ea598"

  strings:
    $s1  = ";})(),(function fuck(){return \"MUs\";})(),(function fuck(){return \"Ik\";})(),(function fuck(){return \"Xw\";})(),(function fuc" ascii
    $s2  = "function fuck(){return \"Ik\";})(),(function fuck(){return \"Ar\";})(),(function fuck(){return \"MUs\";})(),(function fuck(){ret" ascii
    $s3  = "nction fuck(){return \"Qh\";})(),(function fuck(){return \"Mw\";})(),(function fuck(){return \"UOe\";})(),(function fuck(){retur" ascii
    $s4  = "nction fuck(){return \"DRx\";})(),(function fuck(){return \"IPu\";})(),(function fuck(){return \"XCr\";})(),(function fuck(){ret" ascii
    $s5  = ")(),(function fuck(){return \"IPu\";})(),(function fuck(){return \"ZLd\";})(),(function fuck(){return \"Za\";})(),(function fuck" ascii
    $s6  = "nction fuck(){return \"Xw\";})(),(function fuck(){return \"Ik\";})(),(function fuck(){return \"Ar\";})(),(function fuck(){return" ascii
    $s7  = "(),(function fuck(){return \"Ar\";})(),(function fuck(){return \"MUs\";})(),(function fuck(){return \"KVh\";})(),(function fuck(" ascii
    $s8  = " fuck(){return \"QTc\";})(),(function fuck(){return \"ADy\";})(),(function fuck(){return \"IPu\";})(),(function fuck(){return \"" ascii
    $s9  = "})(),(function fuck(){return \"Ve\";})(),(function fuck(){return \"MUs\";})(),(function fuck(){return \"RAi\";})(),(function fuc" ascii
    $s10 = "Za\";})(),(function fuck(){return \"IPu\";})(),(function fuck(){return \"XCr\";})(),(function fuck(){return \"FJs\";})(),(functi" ascii

  condition:
    (uint16(0) == 0x2f0a and (all of them)
    ) or (all of them)
}