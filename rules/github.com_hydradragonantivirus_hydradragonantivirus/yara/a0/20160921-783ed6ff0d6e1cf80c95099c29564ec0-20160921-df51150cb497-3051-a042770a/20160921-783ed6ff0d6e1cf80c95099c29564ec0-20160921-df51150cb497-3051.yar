rule _20160921_783ed6ff0d6e1cf80c95099c29564ec0_20160921_df51150cb497_3051 {
  meta:
    description = "datamaliciousorder - from files 20160921_783ed6ff0d6e1cf80c95099c29564ec0.js, 20160921_df51150cb4977f20502f85bfda11d939.js, 20160921_f2abfe62ed227fb547869419a6d3af3c.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "91c59edb0e2a43b5780f865f87a5462b55dab1281045b0a38b38ac155b7d34b6"
    hash2       = "81cf54f681cedb1b59ee2e355f226c046ac83c55ad32ce5241949279bb194bf1"
    hash3       = "843cfa29e93bfa9adfe4410735aacbf939d01a404dc3c507c0562f478b65086f"

  strings:
    $s1 = " fuck(){return \"Wo0\";})(),(function fuck(){return \"OPz\";})(),(function fuck(){return \"IPu\";})(),(function fuck(){return \"" ascii
    $s2 = "\";})(),(function fuck(){return \"USf\";})(),(function fuck(){return \"LGo\";})(),(function fuck(){return \"Xw\";})(),(function " ascii
    $s3 = "\";})(),(function fuck(){return \"UXf\";})(),(function fuck(){return \"MBg\";})(),(function fuck(){return \"OQr\";})(),(function" ascii
    $s4 = "n fuck(){return \"MBg\";})(),(function fuck(){return \"IPu\";})(),(function fuck(){return \"Xw\";})(),(function fuck(){return \"" ascii
    $s5 = "(){return \"Jo\";})(),(function fuck(){return \"MBg\";})(),(function fuck(){return \"Ot\";})(),(function fuck(){return \"UXf\";}" ascii
    $s6 = "IPu\";})(),(function fuck(){return \"CCb\";})(),(function fuck(){return \"Ug\";})(),(function fuck(){return \"UXf\";})(),(functi" ascii
    $s7 = "n \"DRx\";})(),(function fuck(){return \"IPu\";})(),(function fuck(){return \"Ot\";})(),(function fuck(){return \"DAa\";})(),(fu" ascii

  condition:
    (uint16(0) == 0x2f0a and (all of them)
    ) or (all of them)
}