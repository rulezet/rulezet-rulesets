rule _20160921_6c49e33f1abb3ca2b0ff12a4878e38c8_20160921_783ed6ff0d6e_3881 {
  meta:
    description = "datamaliciousorder - from files 20160921_6c49e33f1abb3ca2b0ff12a4878e38c8.js, 20160921_783ed6ff0d6e1cf80c95099c29564ec0.js, 20160921_df51150cb4977f20502f85bfda11d939.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "b2c5f6e5a1ebce2cb0eb54f0d28ea21ab88b07dc646376bb3fc5ce29af1615aa"
    hash2       = "91c59edb0e2a43b5780f865f87a5462b55dab1281045b0a38b38ac155b7d34b6"
    hash3       = "81cf54f681cedb1b59ee2e355f226c046ac83c55ad32ce5241949279bb194bf1"

  strings:
    $s1 = "turn \"CCb\";})(),(function fuck(){return \"IOs\";})(),(function fuck(){return \"UOe\";})(),(function fuck(){return \"IPu\";})()" ascii
    $s2 = "(){return \"IPu\";})(),(function fuck(){return \"Xw\";})(),(function fuck(){return \"Np\";})(),(function fuck(){return \"Xw\";})" ascii
    $s3 = "return \"Ot\";})(),(function fuck(){return \"Ik\";})(),(function fuck(){return \"UOe\";})(),(function fuck(){return \"IPu\";})()" ascii
    $s4 = " \"Jo\";})(),(function fuck(){return \"USf\";})(),(function fuck(){return \"Xw\";})(),(function fuck(){return \"IPu\";})(),(func" ascii
    $s5 = " fuck(){return \"IPu\";})(),(function fuck(){return \"Ug\";})(),(function fuck(){return \"Na\";})(),(function fuck(){return \"IP" ascii
    $s6 = "DWe\";})(),(function fuck(){return \"Ar\";})(),(function fuck(){return \"IPu\";})(),(function fuck(){return \"MBg\";})(),(functi" ascii

  condition:
    (uint16(0) == 0x2f0a and (all of them)
    ) or (all of them)
}