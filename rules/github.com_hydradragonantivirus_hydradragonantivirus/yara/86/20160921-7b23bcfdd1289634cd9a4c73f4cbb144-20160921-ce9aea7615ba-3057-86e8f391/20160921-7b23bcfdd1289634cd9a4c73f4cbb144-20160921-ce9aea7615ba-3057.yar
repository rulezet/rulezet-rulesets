rule _20160921_7b23bcfdd1289634cd9a4c73f4cbb144_20160921_ce9aea7615ba_3057 {
  meta:
    description = "datamaliciousorder - from files 20160921_7b23bcfdd1289634cd9a4c73f4cbb144.js, 20160921_ce9aea7615ba4a71719a9c0d7f838fc1.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "7a94fbc46ac51a544406f9a59bf405cd1e19e8e6681d7feacbc81e5ab7d4a50b"
    hash2       = "1dfc225800b3b802cbdd9312a3198f5eb4bbcdb06d5f9ffd026bb3fb4f5cf4e6"

  strings:
    $s1 = "eturn \"Np\";})(),(function fuck(){return \"DRx\";})(),(function fuck(){return \"Cd\";})(),(function fuck(){return \"KVh\";})()," ascii
    $s2 = "k(){return \"IOs\";})(),(function fuck(){return \"Fv\";})(),(function fuck(){return \"TTs\";})(),(function fuck(){return \"Et\";" ascii
    $s3 = "nction fuck(){return \"Oh\";})(),(function fuck(){return \"Ik\";})(),(function fuck(){return \"IPu\";})(),(function fuck(){retur" ascii
    $s4 = "(),(function fuck(){return \"Oh\";})(),(function fuck(){return \"Zy\";})(),(function fuck(){return \"AUx\";})(),(function fuck()" ascii
    $s5 = "n fuck(){return \"Vb\";})(),(function fuck(){return \"DRx\";})(),(function fuck(){return \"Cd\";})(),(function fuck(){return \"C" ascii
    $s6 = "(){return \"ADy\";})(),(function fuck(){return \"TTs\";})(),(function fuck(){return \"Et\";})(),(function fuck(){return \"To\";}" ascii
    $s7 = " fuck(){return \"GWo\";})(),(function fuck(){return \"Xg\";})(),(function fuck(){return \"Xw\";})(),(function fuck(){return \"IP" ascii

  condition:
    (uint16(0) == 0x2f0a and (all of them)
    ) or (all of them)
}