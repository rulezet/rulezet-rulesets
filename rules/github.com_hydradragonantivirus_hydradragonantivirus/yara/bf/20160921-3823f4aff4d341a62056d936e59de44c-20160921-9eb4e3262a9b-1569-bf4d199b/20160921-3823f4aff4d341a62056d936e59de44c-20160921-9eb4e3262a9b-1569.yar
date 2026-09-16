rule _20160921_3823f4aff4d341a62056d936e59de44c_20160921_9eb4e3262a9b_1569 {
  meta:
    description = "datamaliciousorder - from files 20160921_3823f4aff4d341a62056d936e59de44c.js, 20160921_9eb4e3262a9bc5c5f03ba0b7b62a3347.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "d0b475c02138425371c1df69faa8ac5c3d739764950c4a65034372b4455ac04d"
    hash2       = "03bf8e47f97cab996cc7f2d8147659dc1143ccbe1fd09af6b8689379f7263407"

  strings:
    $s1  = "urn \"Jg\";})(),(function fuck(){return \"USf\";})(),(function fuck(){return \"IPu\";})(),(function fuck(){return \"DRx\";})(),(" ascii
    $s2  = "\";})(),(function fuck(){return \"Xg\";})(),(function fuck(){return \"IOs\";})(),(function fuck(){return \"OQr\";})(),(function " ascii
    $s3  = "on fuck(){return \"Nm\";})(),(function fuck(){return \"YQt\";})(),(function fuck(){return \"Sx\";})(),(function fuck(){return \"" ascii
    $s4  = " \"CTm\";})(),(function fuck(){return \"Oh\";})(),(function fuck(){return \"XHj\";})(),(function fuck(){return \"FJs\";})(),(fun" ascii
    $s5  = "return \"Vb\";})(),(function fuck(){return \"USf\";})(),(function fuck(){return \"Jo\";})(),(function fuck(){return \"Hs\";})()," ascii
    $s6  = "nction fuck(){return \"Pc\";})(),(function fuck(){return \"XHj\";})(),(function fuck(){return \"YAv\";})(),(function fuck(){retu" ascii
    $s7  = "){return \"CTm\";})(),(function fuck(){return \"CTm\";})(),(function fuck(){return \"ILp\";})(),(function fuck(){return \"GNm\";" ascii
    $s8  = "rn \"Ot\";})(),(function fuck(){return \"SUi\";})(),(function fuck(){return \"MOj\";})(),(function fuck(){return \"NKq\";})(),(f" ascii
    $s9  = "urn \"Oh\";})(),(function fuck(){return \"Jh\";})(),(function fuck(){return \"IPu\";})(),(function fuck(){return \"MBg\";})(),(f" ascii
    $s10 = " \"CTm\";})(),(function fuck(){return \"CTm\";})(),(function fuck(){return \"CTm\";})(),(function fuck(){return \"FJs\";})(),(fu" ascii
    $s11 = "tion fuck(){return \"Av\";})(),(function fuck(){return \"OQr\";})(),(function fuck(){return \"Ve\";})(),(function fuck(){return " ascii
    $s12 = " fuck(){return \"IPu\";})(),(function fuck(){return \"XHj\";})(),(function fuck(){return \"Py\";})(),(function fuck(){return \"Y" ascii

  condition:
    (uint16(0) == 0x2f0a and (8 of them)
    ) or (all of them)
}