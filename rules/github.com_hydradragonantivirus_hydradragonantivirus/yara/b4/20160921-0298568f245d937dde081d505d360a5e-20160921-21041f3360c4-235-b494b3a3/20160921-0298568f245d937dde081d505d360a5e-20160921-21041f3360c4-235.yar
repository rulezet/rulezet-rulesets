rule _20160921_0298568f245d937dde081d505d360a5e_20160921_21041f3360c4_235 {
  meta:
    description = "datamaliciousorder - from files 20160921_0298568f245d937dde081d505d360a5e.js, 20160921_21041f3360c455bf09d8b48dda6959f3.js, 20160921_da8c18b9dd89b42c83c09338a42522db.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "5f31455e0194491e66143329dadae1760f33af4219844671541520909cf32d58"
    hash2       = "de559d9fde4fb08962605e84afb3f8e86d21c757f1189b673ed0648e3dd75cd0"
    hash3       = "4541906a912293fb2fd3b2f0762e5641f73d401239307230b5fc4ae411a1c4f0"

  strings:
    $s1  = "ction fuck(){return \"MBg\";})(),(function fuck(){return \"Vb\";})(),(function fuck(){return \"PDf\";})(),(function fuck(){retur" ascii
    $s2  = "Bg\";})(),(function fuck(){return \"LGo\";})(),(function fuck(){return \"Cd\";})(),(function fuck(){return \"Np\";})(),(function" ascii
    $s3  = "nction fuck(){return \"Cd\";})(),(function fuck(){return \"ADy\";})(),(function fuck(){return \"IPu\";})(),(function fuck(){retu" ascii
    $s4  = "urn \"IKv\";})(),(function fuck(){return \"UOe\";})(),(function fuck(){return \"USf\";})(),(function fuck(){return \"USf\";})()," ascii
    $s5  = "fuck(){return \"PDf\";})(),(function fuck(){return \"RAi\";})(),(function fuck(){return \"Np\";})(),(function fuck(){return \"Np" ascii
    $s6  = "\"RAi\";})(),(function fuck(){return \"Cd\";})(),(function fuck(){return \"IRn\";})(),(function fuck(){return \"MBg\";})(),(func" ascii
    $s7  = "){return \"IKv\";})(),(function fuck(){return \"IPu\";})(),(function fuck(){return \"Cd\";})(),(function fuck(){return \"Cd\";})" ascii
    $s8  = "Vb\";})(),(function fuck(){return \"ADy\";})(),(function fuck(){return \"Vb\";})(),(function fuck(){return \"IPu\";})(),(functio" ascii
    $s9  = "k(){return \"IPu\";})(),(function fuck(){return \"OQr\";})(),(function fuck(){return \"YQt\";})(),(function fuck(){return \"Wo0" ascii
    $s10 = "),(function fuck(){return \"MBg\";})(),(function fuck(){return \"PDf\";})(),(function fuck(){return \"Vb\";})(),(function fuck()" ascii
    $s11 = "on fuck(){return \"QTc\";})(),(function fuck(){return \"OQr\";})(),(function fuck(){return \"XHj\";})(),(function fuck(){return " ascii
    $s12 = "tion fuck(){return \"GWo\";})(),(function fuck(){return \"Dc\";})(),(function fuck(){return \"LGo\";})(),(function fuck(){return" ascii
    $s13 = "),(function fuck(){return \"Vb\";})(),(function fuck(){return \"Cd\";})(),(function fuck(){return \"Vb\";})(),(function fuck(){r" ascii
    $s14 = "ion fuck(){return \"Vb\";})(),(function fuck(){return \"Vb\";})(),(function fuck(){return \"PDf\";})(),(function fuck(){return " ascii
    $s15 = "Ts\";})(),(function fuck(){return \"LGo\";})(),(function fuck(){return \"Cd\";})(),(function fuck(){return \"USf\";})(),(functio" ascii
    $s16 = "TTs\";})(),(function fuck(){return \"Vb\";})(),(function fuck(){return \"USf\";})(),(function fuck(){return \"UOe\";})(),(functi" ascii
    $s17 = "})(),(function fuck(){return \"IPu\";})(),(function fuck(){return \"PDf\";})(),(function fuck(){return \"UOe\";})(),(function fu" ascii
    $s18 = "})(),(function fuck(){return \"Vb\";})(),(function fuck(){return \"ADy\";})(),(function fuck(){return \"Cd\";})(),(function fuck" ascii
    $s19 = " \"MBg\";})(),(function fuck(){return \"ADy\";})(),(function fuck(){return \"Cd\";})(),(function fuck(){return \"Cd\";})(),(func" ascii
    $s20 = "eturn \"RAi\";})(),(function fuck(){return \"UOe\";})(),(function fuck(){return \"USf\";})(),(function fuck(){return \"NKq\";})(" ascii

  condition:
    (uint16(0) == 0x2f0a and (8 of them)
    ) or (all of them)
}