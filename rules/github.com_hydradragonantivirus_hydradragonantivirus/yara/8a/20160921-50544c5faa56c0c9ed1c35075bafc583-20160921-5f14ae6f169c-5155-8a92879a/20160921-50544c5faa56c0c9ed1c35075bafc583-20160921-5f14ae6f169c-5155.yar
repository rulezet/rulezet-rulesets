rule _20160921_50544c5faa56c0c9ed1c35075bafc583_20160921_5f14ae6f169c_5155 {
  meta:
    description = "datamaliciousorder - from files 20160921_50544c5faa56c0c9ed1c35075bafc583.js, 20160921_5f14ae6f169c53d6d49523d1e13e4ab9.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "978b707f3e5da0fd4a8e7394863db19802410ff1b96376fc2432de59fafc5a69"
    hash2       = "270eb53363684986d2aef11b6b5bb4cd5c5cb316f626e41b627db2cf899b440e"

  strings:
    $s1 = "unction fuck(){return \"IRn\";})(),(function fuck(){return \"MBg\";})(),(function fuck(){return \"Vb\";})(),(function fuck(){ret" ascii
    $s2 = "ction fuck(){return \"Za\";})(),(function fuck(){return \"IPu\";})(),(function fuck(){return \"PDf\";})(),(function fuck(){retur" ascii
    $s3 = "return \"MBg\";})(),(function fuck(){return \"AUx\";})(),(function fuck(){return \"UOe\";})(),(function fuck(){return \"GNm\";})" ascii
    $s4 = "ck(){return \"DWe\";})(),(function fuck(){return \"USf\";})(),(function fuck(){return \"TTs\";})(),(function fuck(){return \"IKv" ascii
    $s5 = "s\";})(),(function fuck(){return \"LGo\";})(),(function fuck(){return \"YQt\";})(),(function fuck(){return \"UOe\";})(),(functio" ascii

  condition:
    (uint16(0) == 0x2f0a and (all of them)
    ) or (all of them)
}