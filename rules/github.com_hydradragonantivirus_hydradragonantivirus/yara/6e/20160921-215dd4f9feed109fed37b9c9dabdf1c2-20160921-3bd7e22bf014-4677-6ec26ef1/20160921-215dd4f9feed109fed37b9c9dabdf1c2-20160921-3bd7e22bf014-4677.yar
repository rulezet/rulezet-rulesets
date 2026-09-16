rule _20160921_215dd4f9feed109fed37b9c9dabdf1c2_20160921_3bd7e22bf014_4677 {
  meta:
    description = "datamaliciousorder - from files 20160921_215dd4f9feed109fed37b9c9dabdf1c2.js, 20160921_3bd7e22bf0147340b20eeb7a825cb9a1.js, 20160921_57d7efd4078096b801e379ee02f0feec.js, 20160921_8b9d3c425718975422f8fe0d71119686.js, 20160921_8f9ae4533bfbaedf1feae61032904250.js, 20160921_abc9044816c2455dc24ac338746b6bd5.js, 20160921_b04f9fe7316d0e86c0046e130e905e37.js, 20160921_cd62091b54940830ea3695d380fd97d8.js, 20160921_d4e094c14df45f61de0e1163f51e03e6.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "710f88c7fda95a8d3e0e04de1ffd81606d227d249d76eb0d7fbeba7a0284a86e"
    hash2       = "fabcf64721727f8848bd26426a6a8b0fdf115e6416d2ce71dfa09efadb821690"
    hash3       = "e568760a55d343665c530313749711c3424bfd35c792b1a8b1d5ad6fa004c9a6"
    hash4       = "523032dc97c061d21e22a215d1568aa470cd8d5f46ddb3bae63dafcde8db3687"
    hash5       = "f093836b93b9b87ed10341ee30bc818ac497c91c6d0dd2b00ab5d3b1822868f9"
    hash6       = "2bb53920235afb1c2d16f013bc118d1df64065eefc10c1b2b9e7a4b133850850"
    hash7       = "58df336ac7568c9f52fedec5d0b900480491f3e65f56c23426010ec745a6bddd"
    hash8       = "e00553588533d1015b71812c5877864382cbfd2a3a204b4cab76c38ee65ce58c"
    hash9       = "2877b2ace685858babd88dd0ef1659f49f21c3f8b907e5b3889ec46bf3a7104a"

  strings:
    $s1 = "k(){return \"UXf\";})(),(function fuck(){return \"Sx\";})(),(function fuck(){return \"Xg\";})(),(function fuck(){return \"UXf\";" ascii
    $s2 = "n \"ZVi\";})(),(function fuck(){return \"Dc\";})(),(function fuck(){return \"Za\";})(),(function fuck(){return \"Mw\";})(),(func" ascii
    $s3 = "nction fuck(){return \"Fv\";})(),(function fuck(){return \"XHj\";})(),(function fuck(){return \"Fv\";})(),(function fuck(){retur" ascii
    $s4 = " fuck(){return \"Na\";})(),(function fuck(){return \"IOs\";})(),(function fuck(){return \"Ik\";})(),(function fuck(){return \"UX" ascii
    $s5 = ",(function fuck(){return \"KVh\";})(),(function fuck(){return \"ZWu\";})(),(function fuck(){return \"UXf\";})(),(function fuck()" ascii

  condition:
    (uint16(0) == 0x2f0a and (all of them)
    ) or (all of them)
}