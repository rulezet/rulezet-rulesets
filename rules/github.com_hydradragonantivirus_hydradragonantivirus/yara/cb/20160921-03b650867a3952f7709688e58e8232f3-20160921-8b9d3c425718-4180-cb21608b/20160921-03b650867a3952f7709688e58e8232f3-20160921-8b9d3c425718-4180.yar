rule _20160921_03b650867a3952f7709688e58e8232f3_20160921_8b9d3c425718_4180 {
  meta:
    description = "datamaliciousorder - from files 20160921_03b650867a3952f7709688e58e8232f3.js, 20160921_8b9d3c425718975422f8fe0d71119686.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "a775853212fe6663d7c077a64c0d4c851d4b7f261a6c0846b4552b556e12a5fe"
    hash2       = "523032dc97c061d21e22a215d1568aa470cd8d5f46ddb3bae63dafcde8db3687"

  strings:
    $s1 = "(function fuck(){return \"Jo\";})(),(function fuck(){return \"Jo\";})(),(function fuck(){return \"Vb\";})(),(function fuck(){ret" ascii
    $s2 = "uck(){return \"RAi\";})(),(function fuck(){return \"Vb\";})(),(function fuck(){return \"Np\";})(),(function fuck(){return \"IRn" ascii
    $s3 = "),(function fuck(){return \"UOe\";})(),(function fuck(){return \"Hs\";})(),(function fuck(){return \"ADy\";})(),(function fuck()" ascii
    $s4 = "ction fuck(){return \"TTs\";})(),(function fuck(){return \"Vb\";})(),(function fuck(){return \"ADy\";})(),(function fuck(){retur" ascii
    $s5 = "k(){return \"Wo\";})(),(function fuck(){return \"Zy\";})(),(function fuck(){return \"Za\";})(),(function fuck(){return \"IPu\";}" ascii

  condition:
    (uint16(0) == 0x2f0a and (all of them)
    ) or (all of them)
}