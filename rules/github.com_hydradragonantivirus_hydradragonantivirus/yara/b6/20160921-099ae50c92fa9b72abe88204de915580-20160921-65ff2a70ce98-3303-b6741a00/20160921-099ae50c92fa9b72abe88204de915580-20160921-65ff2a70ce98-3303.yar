rule _20160921_099ae50c92fa9b72abe88204de915580_20160921_65ff2a70ce98_3303 {
  meta:
    description = "datamaliciousorder - from files 20160921_099ae50c92fa9b72abe88204de915580.js, 20160921_65ff2a70ce98d58243fbbdf4849b9c40.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "344e6822e369c3beb064ffee655d0ce0db901d1bada577cd8f338fc2aec06cb8"
    hash2       = "4be01014513bc9c23e14a62953fb7d9f955467208a844109b10c685b1f9c4f29"

  strings:
    $s1 = "eturn \"AUx\";})(),(function fuck(){return \"MOj\";})(),(function fuck(){return \"NKq\";})(),(function fuck(){return \"Ug\";})()" ascii
    $s2 = "ck(){return \"CTm\";})(),(function fuck(){return \"CTm\";})(),(function fuck(){return \"GJx\";})(),(function fuck(){return \"Nm" ascii
    $s3 = "Ve\";})(),(function fuck(){return \"Cd\";})(),(function fuck(){return \"IPu\";})(),(function fuck(){return \"DRx\";})(),(functio" ascii
    $s4 = "){return \"IPu\";})(),(function fuck(){return \"MIl\";})(),(function fuck(){return \"KVh\";})(),(function fuck(){return \"Cd\";}" ascii
    $s5 = "){return \"DRx\";})(),(function fuck(){return \"IPu\";})(),(function fuck(){return \"XFd\";})(),(function fuck(){return \"Yk\";}" ascii
    $s6 = "0\";})(),(function fuck(){return \"SUi\";})(),(function fuck(){return \"GNm\";})(),(function fuck(){return \"IPu\";})(),(functio" ascii

  condition:
    (uint16(0) == 0x2f0a and (all of them)
    ) or (all of them)
}