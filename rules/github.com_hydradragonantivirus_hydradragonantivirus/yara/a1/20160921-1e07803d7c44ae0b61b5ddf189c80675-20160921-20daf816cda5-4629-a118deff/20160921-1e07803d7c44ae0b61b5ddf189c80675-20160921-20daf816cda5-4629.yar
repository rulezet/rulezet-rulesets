rule _20160921_1e07803d7c44ae0b61b5ddf189c80675_20160921_20daf816cda5_4629 {
  meta:
    description = "datamaliciousorder - from files 20160921_1e07803d7c44ae0b61b5ddf189c80675.js, 20160921_20daf816cda5af37e984359023f15db2.js, 20160921_460a913db46b41c41035cc210ed5fba0.js, 20160921_5230866e44eda4e054d929933fdfdae1.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "1a50e95e48071d391fd7544518c3c0394e9cde9051c76cf311992966b7414cc8"
    hash2       = "a45ccf6470d4ee194ed220125c42c5ac5d7c4b8a46cce738c6d12e9cc0bafea8"
    hash3       = "99bd08fbf869b4c9520d81d5b17512d87856474b8cf260494d0c88a47e0d37c9"
    hash4       = "4b11d10d6c2a935fa29f47c13ee54d426aac8d667f3bc2f79681ac7e4d365c76"

  strings:
    $s1 = "\"Ot\";})(),(function fuck(){return \"XCr\";})(),(function fuck(){return \"MUs\";})(),(function fuck(){return \"MOj\";})(),(func" ascii
    $s2 = "ck(){return \"IPu\";})(),(function fuck(){return \"Qh\";})(),(function fuck(){return \"SUi\";})(),(function fuck(){return \"LGo" ascii
    $s3 = "(function fuck(){return \"DRx\";})(),(function fuck(){return \"XHj\";})(),(function fuck(){return \"GJx\";})(),(function fuck(){" ascii
    $s4 = "})(),(function fuck(){return \"DWe\";})(),(function fuck(){return \"Ik\";})(),(function fuck(){return \"Np\";})(),(function fuck" ascii
    $s5 = " \"ZVi\";})(),(function fuck(){return \"Jo\";})(),(function fuck(){return \"IPu\";})(),(function fuck(){return \"DRx\";})(),(fun" ascii

  condition:
    (uint16(0) == 0x2f0a and (all of them)
    ) or (all of them)
}