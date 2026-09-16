rule _20160921_bfdb187f27d136f64e05f0dcf2ee4914_20160921_d29f34806a7d_4049 {
  meta:
    description = "datamaliciousorder - from files 20160921_bfdb187f27d136f64e05f0dcf2ee4914.js, 20160921_d29f34806a7d94f2bbb7a733fc4c43bc.js, 20160921_dd3003e8f16270410cd847da3878f1fc.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "cbf2173e7b067de6ce6bf189ba38c78f3f0d97a7e6685c0191e08885badfeb3e"
    hash2       = "70ffc02d6ba6dee7d11e2b608cd1544f99d837ffc746455c17b70d5b07ba0ac9"
    hash3       = "484cc3f4c9cc3a29ae3ad53bb6d47be99d119531836a636c664a77fc891b38fc"

  strings:
    $s1 = "(){return \"IKv\";})(),(function fuck(){return \"IPu\";})(),(function fuck(){return \"Jo\";})(),(function fuck(){return \"Vb\";}" ascii
    $s2 = "rn \"RAi\";})(),(function fuck(){return \"TTs\";})(),(function fuck(){return \"ADy\";})(),(function fuck(){return \"Jo\";})(),(f" ascii
    $s3 = "ion fuck(){return \"LGo\";})(),(function fuck(){return \"Jo\";})(),(function fuck(){return \"IPu\";})(),(function fuck(){return " ascii
    $s4 = "\"MBg\";})(),(function fuck(){return \"Hs\";})(),(function fuck(){return \"RAi\";})(),(function fuck(){return \"LGo\";})(),(func" ascii
    $s5 = "s\";})(),(function fuck(){return \"Vb\";})(),(function fuck(){return \"Hs\";})(),(function fuck(){return \"Jo\";})(),(function f" ascii
    $s6 = "\"UOe\";})(),(function fuck(){return \"Np\";})(),(function fuck(){return \"Jo\";})(),(function fuck(){return \"IPu\";})(),(funct" ascii

  condition:
    (uint16(0) == 0x2f0a and (all of them)
    ) or (all of them)
}