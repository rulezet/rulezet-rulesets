rule _20160921_b714100d69b955de920a302ff8bef7db_20160921_d0ae6acc5cc4_1520 {
  meta:
    description = "datamaliciousorder - from files 20160921_b714100d69b955de920a302ff8bef7db.js, 20160921_d0ae6acc5cc4f52f8d5df0b47ef8659a.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "fc43d54db3c24d6f7ce2d47a45ffcd0768d5cfe90e405322e477be98fe4a8170"
    hash2       = "8cde265a6a44d9e9f86f351959c030a86800d101b5b5ca057ac1cdc5c5a1e38d"

  strings:
    $s1  = "on fuck(){return \"ADy\";})(),(function fuck(){return \"TTs\";})(),(function fuck(){return \"Oh\";})(),(function fuck(){return " ascii
    $s2  = "turn \"Oh\";})(),(function fuck(){return \"Zy\";})(),(function fuck(){return \"AUx\";})(),(function fuck(){return \"IRn\";})(),(" ascii
    $s3  = "tion fuck(){return \"DHd\";})(),(function fuck(){return \"NKq\";})(),(function fuck(){return \"GNm\";})(),(function fuck(){retur" ascii
    $s4  = "\"YAv\";})(),(function fuck(){return \"ADy\";})(),(function fuck(){return \"TTs\";})(),(function fuck(){return \"XHj\";})(),(fun" ascii
    $s5  = "ck(){return \"YQt\";})(),(function fuck(){return \"Ik\";})(),(function fuck(){return \"Hs\";})(),(function fuck(){return \"IRn\"" ascii
    $s6  = "})(),(function fuck(){return \"Dc\";})(),(function fuck(){return \"PDf\";})(),(function fuck(){return \"Pc\";})(),(function fuck" ascii
    $s7  = "ion fuck(){return \"MIl\";})(),(function fuck(){return \"Jg\";})(),(function fuck(){return \"RAi\";})(),(function fuck(){return " ascii
    $s8  = "unction fuck(){return \"MBg\";})(),(function fuck(){return \"Ug\";})(),(function fuck(){return \"Sx\";})(),(function fuck(){retu" ascii
    $s9  = ",(function fuck(){return \"Zy\";})(),(function fuck(){return \"Jh\";})(),(function fuck(){return \"USf\";})(),(function fuck(){r" ascii
    $s10 = "rn \"Sx\";})(),(function fuck(){return \"MOj\";})(),(function fuck(){return \"NKq\";})(),(function fuck(){return \"GNm\";})(),(f" ascii
    $s11 = "n fuck(){return \"YQt\";})(),(function fuck(){return \"Dc\";})(),(function fuck(){return \"IPu\";})(),(function fuck(){return \"" ascii
    $s12 = ";})(),(function fuck(){return \"OQr\";})(),(function fuck(){return \"XCr\";})(),(function fuck(){return \"KVh\";})(),(function f" ascii
    $s13 = "return \"DRx\";})(),(function fuck(){return \"Yk\";})(),(function fuck(){return \"EHo\";})(),(function fuck(){return \"DRx\";})(" ascii

  condition:
    (uint16(0) == 0x2f0a and (8 of them)
    ) or (all of them)
}