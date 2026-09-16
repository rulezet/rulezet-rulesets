rule _20160921_73310531aa4a1df7337a6ef42003ce5e_20160921_97811319fb50_5402 {
  meta:
    description = "datamaliciousorder - from files 20160921_73310531aa4a1df7337a6ef42003ce5e.js, 20160921_97811319fb50bbd834b521ddcbb35712.js, 20160921_d0ae6acc5cc4f52f8d5df0b47ef8659a.js, 20160921_d72e05128386ec5185fa7c82a29fe618.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "c1f6942ac4bb494bebef47181bbb9c9fe04d3d155e4bc18b2ff21e74c6592f78"
    hash2       = "4105b34a1f3797b1fc5f9b5d7f49d995c2796d5876f07b87b344f6c7e8c0625e"
    hash3       = "8cde265a6a44d9e9f86f351959c030a86800d101b5b5ca057ac1cdc5c5a1e38d"
    hash4       = "72502e65294651208a74590dc961703c09931d4341f59214d7303b271ca8abd5"

  strings:
    $s1 = "unction fuck(){return \"YQt\";})(),(function fuck(){return \"Za\";})(),(function fuck(){return \"IRn\";})(),(function fuck(){ret" ascii
    $s2 = "nction fuck(){return \"IPu\";})(),(function fuck(){return \"Ve\";})(),(function fuck(){return \"Za\";})(),(function fuck(){retur" ascii
    $s3 = "on fuck(){return \"Sx\";})(),(function fuck(){return \"OQr\";})(),(function fuck(){return \"Qh\";})(),(function fuck(){return \"" ascii
    $s4 = "fuck(){return \"Jh\";})(),(function fuck(){return \"MOj\";})(),(function fuck(){return \"GNm\";})(),(function fuck(){return \"Bz" ascii
    $s5 = "ion fuck(){return \"Za\";})(),(function fuck(){return \"Jg\";})(),(function fuck(){return \"GNm\";})(),(function fuck(){return " ascii

  condition:
    (uint16(0) == 0x2f0a and (all of them)
    ) or (all of them)
}