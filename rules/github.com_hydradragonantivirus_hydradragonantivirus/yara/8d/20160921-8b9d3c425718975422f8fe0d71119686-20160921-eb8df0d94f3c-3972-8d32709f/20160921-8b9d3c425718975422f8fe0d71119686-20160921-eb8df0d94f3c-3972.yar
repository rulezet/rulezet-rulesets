rule _20160921_8b9d3c425718975422f8fe0d71119686_20160921_eb8df0d94f3c_3972 {
  meta:
    description = "datamaliciousorder - from files 20160921_8b9d3c425718975422f8fe0d71119686.js, 20160921_eb8df0d94f3c78c9cec0bde62ab2e57e.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "523032dc97c061d21e22a215d1568aa470cd8d5f46ddb3bae63dafcde8db3687"
    hash2       = "768a9ba5aee8702bd0d4c71ccae6016847556423c2ece30b15169aaa7731f27b"

  strings:
    $s1 = "Tm\";})(),(function fuck(){return \"GNm\";})(),(function fuck(){return \"Bz\";})(),(function fuck(){return \"ZVi\";})(),(functio" ascii
    $s2 = "ion fuck(){return \"Ai\";})(),(function fuck(){return \"Xg\";})(),(function fuck(){return \"IPu\";})(),(function fuck(){return " ascii
    $s3 = "rn \"Hs\";})(),(function fuck(){return \"Hs\";})(),(function fuck(){return \"Hs\";})(),(function fuck(){return \"Hs\";})(),(func" ascii
    $s4 = " \"Oh\";})(),(function fuck(){return \"Ai\";})(),(function fuck(){return \"Xg\";})(),(function fuck(){return \"TTs\";})(),(funct" ascii
    $s5 = "(){return \"PDf\";})(),(function fuck(){return \"NKq\";})(),(function fuck(){return \"IPu\";})(),(function fuck(){return \"ZWu\"" ascii
    $s6 = "k(){return \"IPu\";})(),(function fuck(){return \"Cs\";})(),(function fuck(){return \"IPu\";})(),(function fuck(){return \"PDf\"" ascii

  condition:
    (uint16(0) == 0x2f0a and (all of them)
    ) or (all of them)
}