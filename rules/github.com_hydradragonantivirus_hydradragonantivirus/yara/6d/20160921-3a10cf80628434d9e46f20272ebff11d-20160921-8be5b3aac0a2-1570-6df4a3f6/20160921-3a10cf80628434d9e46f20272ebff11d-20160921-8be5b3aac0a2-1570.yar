rule _20160921_3a10cf80628434d9e46f20272ebff11d_20160921_8be5b3aac0a2_1570 {
  meta:
    description = "datamaliciousorder - from files 20160921_3a10cf80628434d9e46f20272ebff11d.js, 20160921_8be5b3aac0a2f47acb168b56c6f880bf.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "c217c4eb7bba8a6770bdd6609635a67fc8772b37668310875b4f4f1ff0b472c2"
    hash2       = "344d7dd8865545f9f4c1045a85547b4140c66621aeedeb02bf60ff4598ff6930"

  strings:
    $s1  = "n \"GWo\";})(),(function fuck(){return \"EHo\";})(),(function fuck(){return \"IPu\";})(),(function fuck(){return \"DRx\";})(),(f" ascii
    $s2  = "ion fuck(){return \"XCr\";})(),(function fuck(){return \"YAv\";})(),(function fuck(){return \"Np\";})(),(function fuck(){return " ascii
    $s3  = "urn \"GWo\";})(),(function fuck(){return \"DAa\";})(),(function fuck(){return \"Np\";})(),(function fuck(){return \"IPu\";})(),(" ascii
    $s4  = "n fuck(){return \"MBg\";})(),(function fuck(){return \"Wo\";})(),(function fuck(){return \"Jo\";})(),(function fuck(){return \"Y" ascii
    $s5  = "fuck(){return \"IPu\";})(),(function fuck(){return \"Hs\";})(),(function fuck(){return \"EHo\";})(),(function fuck(){return \"Np" ascii
    $s6  = ",(function fuck(){return \"Np\";})(),(function fuck(){return \"IRn\";})(),(function fuck(){return \"NKq\";})(),(function fuck(){" ascii
    $s7  = " \"To\";})(),(function fuck(){return \"ZWu\";})(),(function fuck(){return \"AUx\";})(),(function fuck(){return \"IPu\";})(),(fun" ascii
    $s8  = "rn \"We\";})(),(function fuck(){return \"AUx\";})(),(function fuck(){return \"IPu\";})(),(function fuck(){return \"DRx\";})(),(f" ascii
    $s9  = "CCb\";})(),(function fuck(){return \"SUi\";})(),(function fuck(){return \"Cd\";})(),(function fuck(){return \"MOj\";})(),(functi" ascii
    $s10 = "ck(){return \"DRx\";})(),(function fuck(){return \"IPu\";})(),(function fuck(){return \"Ai\";})(),(function fuck(){return \"AUx" ascii
    $s11 = "),(function fuck(){return \"ADy\";})(),(function fuck(){return \"TTs\";})(),(function fuck(){return \"Hs\";})(),(function fuck()" ascii
    $s12 = "fuck(){return \"IPu\";})(),(function fuck(){return \"XFd\";})(),(function fuck(){return \"Nm\";})(),(function fuck(){return \"QT" ascii

  condition:
    (uint16(0) == 0x2f0a and (8 of them)
    ) or (all of them)
}