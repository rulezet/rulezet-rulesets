rule _20160921_70fc4d2c06ba17e1c952591e28e14cf8_20160921_e6977bb87c75_2503 {
  meta:
    description = "datamaliciousorder - from files 20160921_70fc4d2c06ba17e1c952591e28e14cf8.js, 20160921_e6977bb87c752a8f54937489e4d135c8.js, 20160921_f42ed060a223d31bf315f08c4c668579.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "439af0812c2462e15038b6b3de132befd472f89a6810bf0f930acba54e4873ad"
    hash2       = "b2ce1297f179a619d69aa5fa99bb53216eba4d290e545dddda5d0a561f760ec0"
    hash3       = "e1af3f6144c617b4734d9d1f2ae999f7e6d3a46f08760085978213f7cbc38bce"

  strings:
    $s1 = "(){return \"Zy\";})(),(function fuck(){return \"Jo\";})(),(function fuck(){return \"Ve\";})(),(function fuck(){return \"Vb\";})(" ascii
    $s2 = "(function fuck(){return \"DRx\";})(),(function fuck(){return \"Wo0\";})(),(function fuck(){return \"Py\";})(),(function fuck(){r" ascii
    $s3 = "fuck(){return \"OQr\";})(),(function fuck(){return \"To\";})(),(function fuck(){return \"Jh\";})(),(function fuck(){return \"UOe" ascii
    $s4 = "(){return \"Za\";})(),(function fuck(){return \"IPu\";})(),(function fuck(){return \"CCb\";})(),(function fuck(){return \"IOs\";" ascii
    $s5 = "unction fuck(){return \"IPu\";})(),(function fuck(){return \"YQt\";})(),(function fuck(){return \"We\";})(),(function fuck(){ret" ascii
    $s6 = "n \"XCr\";})(),(function fuck(){return \"Ve\";})(),(function fuck(){return \"Cd\";})(),(function fuck(){return \"DRx\";})(),(fun" ascii
    $s7 = "\"DRx\";})(),(function fuck(){return \"Zy\";})(),(function fuck(){return \"Sx\";})(),(function fuck(){return \"DRx\";})(),(funct" ascii
    $s8 = "nction fuck(){return \"PDf\";})(),(function fuck(){return \"MBg\";})(),(function fuck(){return \"YQt\";})(),(function fuck(){ret" ascii

  condition:
    (uint16(0) == 0x2f0a and (all of them)
    ) or (all of them)
}