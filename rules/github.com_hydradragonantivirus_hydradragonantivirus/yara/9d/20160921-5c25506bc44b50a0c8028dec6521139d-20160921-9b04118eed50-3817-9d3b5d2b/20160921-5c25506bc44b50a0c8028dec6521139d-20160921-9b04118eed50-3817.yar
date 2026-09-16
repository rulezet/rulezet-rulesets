rule _20160921_5c25506bc44b50a0c8028dec6521139d_20160921_9b04118eed50_3817 {
  meta:
    description = "datamaliciousorder - from files 20160921_5c25506bc44b50a0c8028dec6521139d.js, 20160921_9b04118eed50c5e7331c4157a5c4dfc8.js, 20160921_da8c18b9dd89b42c83c09338a42522db.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "b6178db9a292199c6992547ad654bf7056fa7f33310f29988e468f0cad5ed707"
    hash2       = "fdb29344d617d9ae88ae6d7109bec25567e1c486cbb28c248a65e9f2a678c75d"
    hash3       = "4541906a912293fb2fd3b2f0762e5641f73d401239307230b5fc4ae411a1c4f0"

  strings:
    $s1 = "uck(){return \"Za\";})(),(function fuck(){return \"IPu\";})(),(function fuck(){return \"ZWu\";})(),(function fuck(){return \"Sx" ascii
    $s2 = "turn \"SUi\";})(),(function fuck(){return \"UOe\";})(),(function fuck(){return \"IPu\";})(),(function fuck(){return \"DRx\";})()" ascii
    $s3 = "turn \"RAi\";})(),(function fuck(){return \"RAi\";})(),(function fuck(){return \"OPz\";})(),(function fuck(){return \"IPu\";})()" ascii
    $s4 = "ck(){return \"QTc\";})(),(function fuck(){return \"Vb\";})(),(function fuck(){return \"OPz\";})(),(function fuck(){return \"IPu" ascii
    $s5 = "ion fuck(){return \"Np\";})(),(function fuck(){return \"UOe\";})(),(function fuck(){return \"RAi\";})(),(function fuck(){return " ascii
    $s6 = "fuck(){return \"DRx\";})(),(function fuck(){return \"IPu\";})(),(function fuck(){return \"ZWu\";})(),(function fuck(){return \"D" ascii

  condition:
    (uint16(0) == 0x2f0a and (all of them)
    ) or (all of them)
}