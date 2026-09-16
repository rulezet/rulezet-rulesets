rule _20160921_70fc4d2c06ba17e1c952591e28e14cf8_20160921_f42ed060a223_64 {
  meta:
    description = "datamaliciousorder - from files 20160921_70fc4d2c06ba17e1c952591e28e14cf8.js, 20160921_f42ed060a223d31bf315f08c4c668579.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "439af0812c2462e15038b6b3de132befd472f89a6810bf0f930acba54e4873ad"
    hash2       = "e1af3f6144c617b4734d9d1f2ae999f7e6d3a46f08760085978213f7cbc38bce"

  strings:
    $s1  = "fuck(){return \"DRx\";})(),(function fuck(){return \"IPu\";})(),(function fuck(){return \"PDf\";})(),(function fuck(){return \"V" ascii
    $s2  = "eturn \"Xw\";})(),(function fuck(){return \"KVh\";})(),(function fuck(){return \"FJs\";})(),(function fuck(){return \"QTc\";})()" ascii
    $s3  = " fuck(){return \"IPu\";})(),(function fuck(){return \"Xw\";})(),(function fuck(){return \"Py\";})(),(function fuck(){return \"Xg" ascii
    $s4  = "ction fuck(){return \"IPu\";})(),(function fuck(){return \"We\";})(),(function fuck(){return \"MUs\";})(),(function fuck(){retur" ascii
    $s5  = "){return \"SUi\";})(),(function fuck(){return \"Cd\";})(),(function fuck(){return \"OPz\";})(),(function fuck(){return \"IPu\";}" ascii
    $s6  = "n \"Wo\";})(),(function fuck(){return \"CCb\";})(),(function fuck(){return \"MUs\";})(),(function fuck(){return \"IPu\";})(),(fu" ascii
    $s7  = "urn \"IPu\";})(),(function fuck(){return \"Xw\";})(),(function fuck(){return \"YAv\";})(),(function fuck(){return \"ADy\";})(),(" ascii
    $s8  = "Dy\";})(),(function fuck(){return \"DAa\";})(),(function fuck(){return \"Xw\";})(),(function fuck(){return \"IPu\";})(),(functio" ascii
    $s9  = "w\";})(),(function fuck(){return \"Ik\";})(),(function fuck(){return \"Ar\";})(),(function fuck(){return \"KVh\";})(),(function " ascii
    $s10 = "\";})(),(function fuck(){return \"Jh\";})(),(function fuck(){return \"ADy\";})(),(function fuck(){return \"IPu\";})(),(function " ascii
    $s11 = "return \"MUs\";})(),(function fuck(){return \"Ik\";})(),(function fuck(){return \"Xw\";})(),(function fuck(){return \"IPu\";})()" ascii
    $s12 = "n \"IPu\";})(),(function fuck(){return \"Et\";})(),(function fuck(){return \"Zy\";})(),(function fuck(){return \"DAa\";})(),(fun" ascii
    $s13 = "nction fuck(){return \"Cd\";})(),(function fuck(){return \"UOe\";})(),(function fuck(){return \"IRn\";})(),(function fuck(){retu" ascii
    $s14 = "){return \"DWe\";})(),(function fuck(){return \"Dc\";})(),(function fuck(){return \"IPu\";})(),(function fuck(){return \"DRx\";}" ascii
    $s15 = "n \"Ve\";})(),(function fuck(){return \"OQr\";})(),(function fuck(){return \"Wo\";})(),(function fuck(){return \"FJs\";})(),(fun" ascii
    $s16 = "eturn \"IPu\";})(),(function fuck(){return \"Xw\";})(),(function fuck(){return \"Mw\";})(),(function fuck(){return \"Ar\";})(),(" ascii
    $s17 = "fuck(){return \"TTs\";})(),(function fuck(){return \"PDf\";})(),(function fuck(){return \"Cd\";})(),(function fuck(){return \"AD" ascii
    $s18 = "(){return \"RAi\";})(),(function fuck(){return \"LGo\";})(),(function fuck(){return \"PDf\";})(),(function fuck(){return \"UOe\"" ascii
    $s19 = "unction fuck(){return \"Za\";})(),(function fuck(){return \"IPu\";})(),(function fuck(){return \"Nm\";})(),(function fuck(){retu" ascii
    $s20 = "urn \"GWo\";})(),(function fuck(){return \"Jh\";})(),(function fuck(){return \"IPu\";})(),(function fuck(){return \"MBg\";})(),(" ascii

  condition:
    (uint16(0) == 0x2f0a and (8 of them)
    ) or (all of them)
}