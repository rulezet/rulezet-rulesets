rule _20160921_962ed1e894cd91f421ad984310ce3140_20160921_acea633b7398_5561 {
  meta:
    description = "datamaliciousorder - from files 20160921_962ed1e894cd91f421ad984310ce3140.js, 20160921_acea633b73985995ce9764bf94db0972.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "5ddab3f025feef0c562b4f7f707a08e5d6502c7b7178d3d6367d05bae0018033"
    hash2       = "dd77df78b3a755b016a27bbcac8fe7c015ab04472e2ca2d2d9aa476befb3148a"

  strings:
    $s1 = "rn \"PDf\";})(),(function fuck(){return \"ZLd\";})(),(function fuck(){return \"Sx\";})(),(function fuck(){return \"RAi\";})(),(f" ascii
    $s2 = "(function fuck(){return \"YQt\";})(),(function fuck(){return \"ADy\";})(),(function fuck(){return \"IRn\";})(),(function fuck(){" ascii
    $s3 = "ck(){return \"IPu\";})(),(function fuck(){return \"XHj\";})(),(function fuck(){return \"Oh\";})(),(function fuck(){return \"Py\"" ascii
    $s4 = "return \"TTs\";})(),(function fuck(){return \"Vb\";})(),(function fuck(){return \"AUx\";})(),(function fuck(){return \"AUx\";})(" ascii
    $s5 = "IPu\";})(),(function fuck(){return \"Ot\";})(),(function fuck(){return \"Za\";})(),(function fuck(){return \"LGo\";})(),(functio" ascii

  condition:
    (uint16(0) == 0x2f0a and (all of them)
    ) or (all of them)
}