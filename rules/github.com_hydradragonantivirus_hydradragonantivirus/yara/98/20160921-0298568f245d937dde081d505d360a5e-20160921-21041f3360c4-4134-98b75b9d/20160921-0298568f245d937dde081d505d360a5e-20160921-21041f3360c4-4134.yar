rule _20160921_0298568f245d937dde081d505d360a5e_20160921_21041f3360c4_4134 {
  meta:
    description = "datamaliciousorder - from files 20160921_0298568f245d937dde081d505d360a5e.js, 20160921_21041f3360c455bf09d8b48dda6959f3.js, 20160921_40f63eff81c24c0b6e27053222902225.js, 20160921_56407ccd21c5f8f4947d4df222e60442.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "5f31455e0194491e66143329dadae1760f33af4219844671541520909cf32d58"
    hash2       = "de559d9fde4fb08962605e84afb3f8e86d21c757f1189b673ed0648e3dd75cd0"
    hash3       = "6b71d253d7ac7dfb797132caac458cf74b81e67304218edbb764243d89e51bb1"
    hash4       = "bec8a0189f43e097fc0815a0bb39f2df50e4c37c7185ad70b3be3b0d17b8dd32"

  strings:
    $s1 = "\"ZWu\";})(),(function fuck(){return \"ZLd\";})(),(function fuck(){return \"YAv\";})(),(function fuck(){return \"IPu\";})(),(fun" ascii
    $s2 = " fuck(){return \"IRn\";})(),(function fuck(){return \"OQr\";})(),(function fuck(){return \"Hs\";})(),(function fuck(){return \"W" ascii
    $s3 = "n \"Sx\";})(),(function fuck(){return \"GNm\";})(),(function fuck(){return \"DRx\";})(),(function fuck(){return \"We\";})(),(fun" ascii
    $s4 = "),(function fuck(){return \"ZVi\";})(),(function fuck(){return \"DRx\";})(),(function fuck(){return \"Zy\";})(),(function fuck()" ascii
    $s5 = "ck(){return \"QTc\";})(),(function fuck(){return \"DRx\";})(),(function fuck(){return \"XCr\";})(),(function fuck(){return \"Na" ascii

  condition:
    (uint16(0) == 0x2f0a and (all of them)
    ) or (all of them)
}