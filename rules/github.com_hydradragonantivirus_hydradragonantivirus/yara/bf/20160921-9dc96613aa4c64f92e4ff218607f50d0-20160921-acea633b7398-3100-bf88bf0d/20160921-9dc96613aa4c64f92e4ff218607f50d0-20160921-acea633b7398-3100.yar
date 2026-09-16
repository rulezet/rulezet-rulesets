rule _20160921_9dc96613aa4c64f92e4ff218607f50d0_20160921_acea633b7398_3100 {
  meta:
    description = "datamaliciousorder - from files 20160921_9dc96613aa4c64f92e4ff218607f50d0.js, 20160921_acea633b73985995ce9764bf94db0972.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "f6c272b2491e06062a7ec30effe81ff00903e7c91b1be85625b1fe6794546c7a"
    hash2       = "dd77df78b3a755b016a27bbcac8fe7c015ab04472e2ca2d2d9aa476befb3148a"

  strings:
    $s1 = "unction fuck(){return \"KVh\";})(),(function fuck(){return \"LGo\";})(),(function fuck(){return \"IRn\";})(),(function fuck(){re" ascii
    $s2 = "k(){return \"DRx\";})(),(function fuck(){return \"IPu\";})(),(function fuck(){return \"Wo0\";})(),(function fuck(){return \"Ot\"" ascii
    $s3 = "\"IPu\";})(),(function fuck(){return \"Oh\";})(),(function fuck(){return \"EHo\";})(),(function fuck(){return \"IPu\";})(),(func" ascii
    $s4 = "OQr\";})(),(function fuck(){return \"Jo\";})(),(function fuck(){return \"SUi\";})(),(function fuck(){return \"YQt\";})(),(functi" ascii
    $s5 = "ction fuck(){return \"ADy\";})(),(function fuck(){return \"TTs\";})(),(function fuck(){return \"Qh\";})(),(function fuck(){retur" ascii
    $s6 = "n fuck(){return \"YQt\";})(),(function fuck(){return \"ADy\";})(),(function fuck(){return \"YQt\";})(),(function fuck(){return " ascii
    $s7 = "fuck(){return \"Nm\";})(),(function fuck(){return \"QTc\";})(),(function fuck(){return \"Vb\";})(),(function fuck(){return \"IPu" ascii

  condition:
    (uint16(0) == 0x2f0a and (all of them)
    ) or (all of them)
}