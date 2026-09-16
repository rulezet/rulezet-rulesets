rule _20160921_2111693a6587de2f8afee1834010d572_20160921_c01f87df9de4_4673 {
  meta:
    description = "datamaliciousorder - from files 20160921_2111693a6587de2f8afee1834010d572.js, 20160921_c01f87df9de4ce5ca88bd5f8e99b8421.js, 20160921_c0cd20cf50e8d47fdd1303227435227a.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "afb04df96413e21fd33fbf65fafdf5fc01cc299acc2cbe099811e60500fbc6d7"
    hash2       = "863f188b1216c3a7a1dc561983400a4e8b6fadded702cf47ee8533061495abc8"
    hash3       = "3d34400bc3cfc9235dbf1a201a7f50b72821566d70727533493e74fbeb8a5514"

  strings:
    $s1 = "n \"OQr\";})(),(function fuck(){return \"USf\";})(),(function fuck(){return \"UOe\";})(),(function fuck(){return \"Vb\";})(),(fu" ascii
    $s2 = ",(function fuck(){return \"Vb\";})(),(function fuck(){return \"Pc\";})(),(function fuck(){return \"GNm\";})(),(function fuck(){r" ascii
    $s3 = "return \"NKq\";})(),(function fuck(){return \"Ug\";})(),(function fuck(){return \"Bz\";})(),(function fuck(){return \"MUs\";})()" ascii
    $s4 = "),(function fuck(){return \"Vb\";})(),(function fuck(){return \"IRn\";})(),(function fuck(){return \"DHd\";})(),(function fuck()" ascii
    $s5 = "eturn \"USf\";})(),(function fuck(){return \"MOj\";})(),(function fuck(){return \"MOj\";})(),(function fuck(){return \"Ug\";})()" ascii

  condition:
    (uint16(0) == 0x2f0a and (all of them)
    ) or (all of them)
}