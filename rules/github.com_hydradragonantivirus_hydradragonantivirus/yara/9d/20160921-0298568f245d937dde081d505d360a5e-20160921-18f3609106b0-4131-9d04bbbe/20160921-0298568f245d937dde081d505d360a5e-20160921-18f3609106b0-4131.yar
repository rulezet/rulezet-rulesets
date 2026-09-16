rule _20160921_0298568f245d937dde081d505d360a5e_20160921_18f3609106b0_4131 {
  meta:
    description = "datamaliciousorder - from files 20160921_0298568f245d937dde081d505d360a5e.js, 20160921_18f3609106b0af59da0b1200fe14abc1.js, 20160921_21041f3360c455bf09d8b48dda6959f3.js, 20160921_de03e8e8d98da4b7d17147c979ce9ff8.js, 20160921_e4c63c3b699efd2f5fe2739b016a938a.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "5f31455e0194491e66143329dadae1760f33af4219844671541520909cf32d58"
    hash2       = "95fb9e6292746461417b0e539747d500c780ad17cb775a9db031f77eaa53a3e2"
    hash3       = "de559d9fde4fb08962605e84afb3f8e86d21c757f1189b673ed0648e3dd75cd0"
    hash4       = "aa4eb617dd497a7ea1d016d98ce4ca8e81e13b4e240c42d46d01e84e617a150b"
    hash5       = "9d5d6c2986818649619806d890aad49cda8d0da47fe67f38388e5441a53382a0"

  strings:
    $s1 = "n fuck(){return \"IPu\";})(),(function fuck(){return \"YQt\";})(),(function fuck(){return \"Ve\";})(),(function fuck(){return \"" ascii
    $s2 = "(),(function fuck(){return \"MBg\";})(),(function fuck(){return \"Hs\";})(),(function fuck(){return \"YAv\";})(),(function fuck(" ascii
    $s3 = "k(){return \"TTs\";})(),(function fuck(){return \"Nm\";})(),(function fuck(){return \"UXf\";})(),(function fuck(){return \"IPu\"" ascii
    $s4 = "ZVi\";})(),(function fuck(){return \"IRn\";})(),(function fuck(){return \"MBg\";})(),(function fuck(){return \"DWe\";})(),(funct" ascii
    $s5 = "turn \"GWo\";})(),(function fuck(){return \"Ik\";})(),(function fuck(){return \"IPu\";})(),(function fuck(){return \"DRx\";})()," ascii

  condition:
    (uint16(0) == 0x2f0a and (all of them)
    ) or (all of them)
}