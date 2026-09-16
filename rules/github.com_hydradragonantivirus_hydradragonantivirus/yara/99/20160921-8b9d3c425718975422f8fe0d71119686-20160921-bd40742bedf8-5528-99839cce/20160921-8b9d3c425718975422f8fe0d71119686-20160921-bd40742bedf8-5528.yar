rule _20160921_8b9d3c425718975422f8fe0d71119686_20160921_bd40742bedf8_5528 {
  meta:
    description = "datamaliciousorder - from files 20160921_8b9d3c425718975422f8fe0d71119686.js, 20160921_bd40742bedf80aa0091b1fafd0a7ba4b.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "523032dc97c061d21e22a215d1568aa470cd8d5f46ddb3bae63dafcde8db3687"
    hash2       = "85233a675e78f03dbcaaf2a32253b0d4a36e5c5e7008041477e560a514d38729"

  strings:
    $s1 = "n fuck(){return \"DRx\";})(),(function fuck(){return \"IPu\";})(),(function fuck(){return \"GJx\";})(),(function fuck(){return " ascii
    $s2 = "})(),(function fuck(){return \"Nm\";})(),(function fuck(){return \"Fv\";})(),(function fuck(){return \"RAi\";})(),(function fuck" ascii
    $s3 = "eturn \"TTs\";})(),(function fuck(){return \"Cd\";})(),(function fuck(){return \"Xg\";})(),(function fuck(){return \"IPu\";})()," ascii
    $s4 = ")(),(function fuck(){return \"UOe\";})(),(function fuck(){return \"PDf\";})(),(function fuck(){return \"ADy\";})(),(function fuc" ascii
    $s5 = "n fuck(){return \"LGo\";})(),(function fuck(){return \"RAi\";})(),(function fuck(){return \"PDf\";})(),(function fuck(){return " ascii

  condition:
    (uint16(0) == 0x2f0a and (all of them)
    ) or (all of them)
}