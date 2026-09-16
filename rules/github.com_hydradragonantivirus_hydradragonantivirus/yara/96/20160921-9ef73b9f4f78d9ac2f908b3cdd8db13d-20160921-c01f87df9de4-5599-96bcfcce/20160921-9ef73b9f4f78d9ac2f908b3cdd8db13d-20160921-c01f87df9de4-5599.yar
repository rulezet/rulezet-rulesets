rule _20160921_9ef73b9f4f78d9ac2f908b3cdd8db13d_20160921_c01f87df9de4_5599 {
  meta:
    description = "datamaliciousorder - from files 20160921_9ef73b9f4f78d9ac2f908b3cdd8db13d.js, 20160921_c01f87df9de4ce5ca88bd5f8e99b8421.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "31bd1528e102f576486e80b1ead7224fc04db7a81b4fbf1ae11c4416b5e4bd57"
    hash2       = "863f188b1216c3a7a1dc561983400a4e8b6fadded702cf47ee8533061495abc8"

  strings:
    $s1 = "eturn \"OQr\";})(),(function fuck(){return \"CCb\";})(),(function fuck(){return \"SUi\";})(),(function fuck(){return \"Cd\";})()" ascii
    $s2 = "n fuck(){return \"DRx\";})(),(function fuck(){return \"IPu\";})(),(function fuck(){return \"XHj\";})(),(function fuck(){return " ascii
    $s3 = "eturn \"Vf\";})(),(function fuck(){return \"XCr\";})(),(function fuck(){return \"AUx\";})(),(function fuck(){return \"USf\";})()" ascii
    $s4 = "turn \"Jo\";})(),(function fuck(){return \"QTc\";})(),(function fuck(){return \"LGo\";})(),(function fuck(){return \"IPu\";})()," ascii
    $s5 = "(),(function fuck(){return \"AUx\";})(),(function fuck(){return \"LGo\";})(),(function fuck(){return \"DRx\";})(),(function fuck" ascii

  condition:
    (uint16(0) == 0x2f0a and (all of them)
    ) or (all of them)
}