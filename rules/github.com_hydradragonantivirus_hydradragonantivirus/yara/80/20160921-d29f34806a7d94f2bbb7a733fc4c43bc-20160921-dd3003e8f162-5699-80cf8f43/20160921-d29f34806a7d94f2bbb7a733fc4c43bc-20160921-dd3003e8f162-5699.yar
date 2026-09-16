rule _20160921_d29f34806a7d94f2bbb7a733fc4c43bc_20160921_dd3003e8f162_5699 {
  meta:
    description = "datamaliciousorder - from files 20160921_d29f34806a7d94f2bbb7a733fc4c43bc.js, 20160921_dd3003e8f16270410cd847da3878f1fc.js, 20160921_eb8df0d94f3c78c9cec0bde62ab2e57e.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "70ffc02d6ba6dee7d11e2b608cd1544f99d837ffc746455c17b70d5b07ba0ac9"
    hash2       = "484cc3f4c9cc3a29ae3ad53bb6d47be99d119531836a636c664a77fc891b38fc"
    hash3       = "768a9ba5aee8702bd0d4c71ccae6016847556423c2ece30b15169aaa7731f27b"

  strings:
    $s1 = "unction fuck(){return \"IKv\";})(),(function fuck(){return \"IPu\";})(),(function fuck(){return \"Hs\";})(),(function fuck(){ret" ascii
    $s2 = "n fuck(){return \"RAi\";})(),(function fuck(){return \"Np\";})(),(function fuck(){return \"Jo\";})(),(function fuck(){return \"N" ascii
    $s3 = "ck(){return \"ADy\";})(),(function fuck(){return \"Hs\";})(),(function fuck(){return \"Np\";})(),(function fuck(){return \"IPu\"" ascii
    $s4 = "})(),(function fuck(){return \"RAi\";})(),(function fuck(){return \"Hs\";})(),(function fuck(){return \"ADy\";})(),(function fuc" ascii
    $s5 = "Oe\";})(),(function fuck(){return \"Hs\";})(),(function fuck(){return \"USf\";})(),(function fuck(){return \"IRn\";})(),(functio" ascii

  condition:
    (uint16(0) == 0x2f0a and (all of them)
    ) or (all of them)
}