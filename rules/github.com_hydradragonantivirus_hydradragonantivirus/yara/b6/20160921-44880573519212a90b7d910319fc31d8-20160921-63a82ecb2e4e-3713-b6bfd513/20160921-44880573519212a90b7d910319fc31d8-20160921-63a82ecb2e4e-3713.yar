rule _20160921_44880573519212a90b7d910319fc31d8_20160921_63a82ecb2e4e_3713 {
  meta:
    description = "datamaliciousorder - from files 20160921_44880573519212a90b7d910319fc31d8.js, 20160921_63a82ecb2e4eb3b0dd878bbec885c469.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "8427ee610833efbf68884e3ec13c4357ae35e1aa0bf8ddc2ffe99b9a7f44fb40"
    hash2       = "0e9de62be8773f33e42da56c84c9c85d07f7c2616909543479f7803e6794a9ef"

  strings:
    $s1 = "tion fuck(){return \"Ot\";})(),(function fuck(){return \"ZWu\";})(),(function fuck(){return \"GWo\";})(),(function fuck(){return" ascii
    $s2 = "fuck(){return \"IPu\";})(),(function fuck(){return \"ZLd\";})(),(function fuck(){return \"KVh\";})(),(function fuck(){return \"I" ascii
    $s3 = "})(),(function fuck(){return \"We\";})(),(function fuck(){return \"ZWu\";})(),(function fuck(){return \"MUs\";})(),(function fuc" ascii
    $s4 = "uck(){return \"IPu\";})(),(function fuck(){return \"Np\";})(),(function fuck(){return \"ADy\";})(),(function fuck(){return \"Py" ascii
    $s5 = " fuck(){return \"TTs\";})(),(function fuck(){return \"ZLd\";})(),(function fuck(){return \"UXf\";})(),(function fuck(){return \"" ascii
    $s6 = "n \"Ai\";})(),(function fuck(){return \"DAa\";})(),(function fuck(){return \"IRn\";})(),(function fuck(){return \"OQr\";})(),(fu" ascii

  condition:
    (uint16(0) == 0x2f0a and (all of them)
    ) or (all of them)
}