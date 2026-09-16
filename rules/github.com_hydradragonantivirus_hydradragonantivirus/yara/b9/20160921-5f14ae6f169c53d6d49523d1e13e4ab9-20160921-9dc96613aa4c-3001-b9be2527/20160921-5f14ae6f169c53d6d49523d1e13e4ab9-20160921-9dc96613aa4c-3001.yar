rule _20160921_5f14ae6f169c53d6d49523d1e13e4ab9_20160921_9dc96613aa4c_3001 {
  meta:
    description = "datamaliciousorder - from files 20160921_5f14ae6f169c53d6d49523d1e13e4ab9.js, 20160921_9dc96613aa4c64f92e4ff218607f50d0.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "270eb53363684986d2aef11b6b5bb4cd5c5cb316f626e41b627db2cf899b440e"
    hash2       = "f6c272b2491e06062a7ec30effe81ff00903e7c91b1be85625b1fe6794546c7a"

  strings:
    $s1 = "u\";})(),(function fuck(){return \"IKv\";})(),(function fuck(){return \"IPu\";})(),(function fuck(){return \"YQt\";})(),(functio" ascii
    $s2 = "unction fuck(){return \"ADy\";})(),(function fuck(){return \"AUx\";})(),(function fuck(){return \"NKq\";})(),(function fuck(){re" ascii
    $s3 = "urn \"TTs\";})(),(function fuck(){return \"LGo\";})(),(function fuck(){return \"LGo\";})(),(function fuck(){return \"YQt\";})()," ascii
    $s4 = "(function fuck(){return \"IRn\";})(),(function fuck(){return \"MBg\";})(),(function fuck(){return \"YQt\";})(),(function fuck(){" ascii
    $s5 = "rn \"IPu\";})(),(function fuck(){return \"MIl\";})(),(function fuck(){return \"Jo\";})(),(function fuck(){return \"FJs\";})(),(f" ascii
    $s6 = "function fuck(){return \"We\";})(),(function fuck(){return \"IOs\";})(),(function fuck(){return \"UOe\";})(),(function fuck(){re" ascii
    $s7 = " \"CTm\";})(),(function fuck(){return \"CTm\";})(),(function fuck(){return \"GJx\";})(),(function fuck(){return \"Et\";})(),(fun" ascii

  condition:
    (uint16(0) == 0x2f0a and (all of them)
    ) or (all of them)
}