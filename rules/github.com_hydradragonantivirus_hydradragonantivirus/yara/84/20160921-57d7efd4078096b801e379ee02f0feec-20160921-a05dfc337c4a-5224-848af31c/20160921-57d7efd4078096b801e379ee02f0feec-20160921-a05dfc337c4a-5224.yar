rule _20160921_57d7efd4078096b801e379ee02f0feec_20160921_a05dfc337c4a_5224 {
  meta:
    description = "datamaliciousorder - from files 20160921_57d7efd4078096b801e379ee02f0feec.js, 20160921_a05dfc337c4ada28e05759b304eef904.js, 20160921_b04f9fe7316d0e86c0046e130e905e37.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "e568760a55d343665c530313749711c3424bfd35c792b1a8b1d5ad6fa004c9a6"
    hash2       = "db6a3cf7e8281867bf38b22cce5a945336377679a1a85ee91d365e41ec94182c"
    hash3       = "58df336ac7568c9f52fedec5d0b900480491f3e65f56c23426010ec745a6bddd"

  strings:
    $s1 = "fuck(){return \"Xg\";})(),(function fuck(){return \"OQr\";})(),(function fuck(){return \"MOj\";})(),(function fuck(){return \"IP" ascii
    $s2 = "turn \"Za\";})(),(function fuck(){return \"GJx\";})(),(function fuck(){return \"Ik\";})(),(function fuck(){return \"Ar\";})(),(f" ascii
    $s3 = "unction fuck(){return \"Pc\";})(),(function fuck(){return \"Fv\";})(),(function fuck(){return \"Mw\";})(),(function fuck(){retur" ascii
    $s4 = "\";})(),(function fuck(){return \"Mw\";})(),(function fuck(){return \"Ve\";})(),(function fuck(){return \"Xg\";})(),(function fu" ascii
    $s5 = "k(){return \"UOe\";})(),(function fuck(){return \"Cd\";})(),(function fuck(){return \"Xw\";})(),(function fuck(){return \"MOj\";" ascii

  condition:
    (uint16(0) == 0x2f0a and (all of them)
    ) or (all of them)
}