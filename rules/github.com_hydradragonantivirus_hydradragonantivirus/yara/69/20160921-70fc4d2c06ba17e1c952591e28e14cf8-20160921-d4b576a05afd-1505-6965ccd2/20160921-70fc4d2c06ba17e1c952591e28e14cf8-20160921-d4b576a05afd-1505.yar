rule _20160921_70fc4d2c06ba17e1c952591e28e14cf8_20160921_d4b576a05afd_1505 {
  meta:
    description = "datamaliciousorder - from files 20160921_70fc4d2c06ba17e1c952591e28e14cf8.js, 20160921_d4b576a05afdcd9649d02e422feb16d3.js, 20160921_f42ed060a223d31bf315f08c4c668579.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "439af0812c2462e15038b6b3de132befd472f89a6810bf0f930acba54e4873ad"
    hash2       = "221c028d5b96ed7d5655800598b47b367ee2d1927826d126b5808db32c9a01f2"
    hash3       = "e1af3f6144c617b4734d9d1f2ae999f7e6d3a46f08760085978213f7cbc38bce"

  strings:
    $s1  = "urn \"CTm\";})(),(function fuck(){return \"CTm\";})(),(function fuck(){return \"Jo\";})(),(function fuck(){return \"Nm\";})(),(f" ascii
    $s2  = "k(){return \"GWo\";})(),(function fuck(){return \"FJs\";})(),(function fuck(){return \"LGo\";})(),(function fuck(){return \"IPu" ascii
    $s3  = "fuck(){return \"Yb\";})(),(function fuck(){return \"IPu\";})(),(function fuck(){return \"Nm\";})(),(function fuck(){return \"ZWu" ascii
    $s4  = "uck(){return \"OQr\";})(),(function fuck(){return \"GJx\";})(),(function fuck(){return \"Nm\";})(),(function fuck(){return \"MUs" ascii
    $s5  = "unction fuck(){return \"Za\";})(),(function fuck(){return \"IRn\";})(),(function fuck(){return \"IKv\";})(),(function fuck(){ret" ascii
    $s6  = "on fuck(){return \"FJs\";})(),(function fuck(){return \"USf\";})(),(function fuck(){return \"NKq\";})(),(function fuck(){return " ascii
    $s7  = "k(){return \"IPu\";})(),(function fuck(){return \"Vb\";})(),(function fuck(){return \"GNm\";})(),(function fuck(){return \"GNm\"" ascii
    $s8  = "d\";})(),(function fuck(){return \"OPz\";})(),(function fuck(){return \"IPu\";})(),(function fuck(){return \"Cd\";})(),(function" ascii
    $s9  = " \"DRx\";})(),(function fuck(){return \"IPu\";})(),(function fuck(){return \"Nm\";})(),(function fuck(){return \"ZWu\";})(),(fun" ascii
    $s10 = "return \"IPu\";})(),(function fuck(){return \"OQr\";})(),(function fuck(){return \"Jo\";})(),(function fuck(){return \"Nm\";})()" ascii
    $s11 = "rn \"MBg\";})(),(function fuck(){return \"Qh\";})(),(function fuck(){return \"DWe\";})(),(function fuck(){return \"UXf\";})(),(f" ascii
    $s12 = "eturn \"UXf\";})(),(function fuck(){return \"IPu\";})(),(function fuck(){return \"Nm\";})(),(function fuck(){return \"ZWu\";})()" ascii
    $s13 = "fuck(){return \"MUs\";})(),(function fuck(){return \"MBg\";})(),(function fuck(){return \"OQr\";})(),(function fuck(){return \"J" ascii

  condition:
    (uint16(0) == 0x2f0a and (8 of them)
    ) or (all of them)
}