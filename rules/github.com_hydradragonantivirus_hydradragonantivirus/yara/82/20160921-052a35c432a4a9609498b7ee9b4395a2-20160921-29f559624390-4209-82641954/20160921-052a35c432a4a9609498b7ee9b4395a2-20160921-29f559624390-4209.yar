rule _20160921_052a35c432a4a9609498b7ee9b4395a2_20160921_29f559624390_4209 {
  meta:
    description = "datamaliciousorder - from files 20160921_052a35c432a4a9609498b7ee9b4395a2.js, 20160921_29f559624390fcbd3c9f89ef4a0d5e1d.js, 20160921_3b2083afdb57ae7e611f6f42c6787c73.js, 20160921_a5297a3430b731f07a8b2bd532530907.js, 20160921_b2419a000449b12cbd6aff3732baf55d.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "209fd59dbb6143d03e0b3619c6d5cc33114cb8e3b4f252eb6d9da074e7636495"
    hash2       = "c15ee6fcf772accd2bb85369b8381c6c2cefb7139e589532becec07720a57867"
    hash3       = "4c81783a1510b3172e1702365554b0e2000709a4e4217a8970aa381c9b357e36"
    hash4       = "3cc34a5e206b8e31e54d9f96ede8214dea00b391969498f92170a493ebd7aa45"
    hash5       = "ea7b5520c177b4adf74565706c3c8ed38eed94f30b6927b0ceb647f7f768a2b5"

  strings:
    $s1 = "ion fuck(){return \"DRx\";})(),(function fuck(){return \"IPu\";})(),(function fuck(){return \"ZWu\";})(),(function fuck(){return" ascii
    $s2 = "(){return \"OQr\";})(),(function fuck(){return \"Hs\";})(),(function fuck(){return \"Wo0\";})(),(function fuck(){return \"ZVi\";" ascii
    $s3 = "\";})(),(function fuck(){return \"DRx\";})(),(function fuck(){return \"We\";})(),(function fuck(){return \"QTc\";})(),(function " ascii
    $s4 = "return \"DRx\";})(),(function fuck(){return \"XCr\";})(),(function fuck(){return \"Na\";})(),(function fuck(){return \"IPu\";})(" ascii
    $s5 = "nction fuck(){return \"DRx\";})(),(function fuck(){return \"Zy\";})(),(function fuck(){return \"Sx\";})(),(function fuck(){retur" ascii

  condition:
    (uint16(0) == 0x2f0a and (all of them)
    ) or (all of them)
}