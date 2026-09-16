rule _20160921_214342143d6b7e971a1c8d2679379cb7_20160921_783ed6ff0d6e_1553 {
  meta:
    description = "datamaliciousorder - from files 20160921_214342143d6b7e971a1c8d2679379cb7.js, 20160921_783ed6ff0d6e1cf80c95099c29564ec0.js, 20160921_e6b8063519cd61bbba9375bf86215501.js, 20160921_f2abfe62ed227fb547869419a6d3af3c.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "8dcc208c118a95c2f88df14e844ed832ee1e06bdf992329e8a721bd7aaa936e8"
    hash2       = "91c59edb0e2a43b5780f865f87a5462b55dab1281045b0a38b38ac155b7d34b6"
    hash3       = "70ad2f9c8f844d4c80b1d4ce0f71f62f74e64671ae11d2d3af8e6ec764993403"
    hash4       = "843cfa29e93bfa9adfe4410735aacbf939d01a404dc3c507c0562f478b65086f"

  strings:
    $s1  = " \"DRx\";})(),(function fuck(){return \"IPu\";})(),(function fuck(){return \"Oh\";})(),(function fuck(){return \"Ug\";})(),(func" ascii
    $s2  = "n \"IPu\";})(),(function fuck(){return \"Nm\";})(),(function fuck(){return \"Wo\";})(),(function fuck(){return \"MUs\";})(),(fun" ascii
    $s3  = "ck(){return \"UOe\";})(),(function fuck(){return \"MBg\";})(),(function fuck(){return \"OQr\";})(),(function fuck(){return \"XFd" ascii
    $s4  = "(){return \"Dc\";})(),(function fuck(){return \"Hs\";})(),(function fuck(){return \"IPu\";})(),(function fuck(){return \"DRx\";}" ascii
    $s5  = "(function fuck(){return \"RAi\";})(),(function fuck(){return \"RAi\";})(),(function fuck(){return \"OPz\";})(),(function fuck(){" ascii
    $s6  = " \"IPu\";})(),(function fuck(){return \"Vb\";})(),(function fuck(){return \"Jo\";})(),(function fuck(){return \"Hs\";})(),(funct" ascii
    $s7  = "(){return \"UOe\";})(),(function fuck(){return \"LGo\";})(),(function fuck(){return \"IRn\";})(),(function fuck(){return \"NKq\"" ascii
    $s8  = "eturn \"YQt\";})(),(function fuck(){return \"QTc\";})(),(function fuck(){return \"IPu\";})(),(function fuck(){return \"DRx\";})(" ascii
    $s9  = "unction fuck(){return \"IPu\";})(),(function fuck(){return \"YQt\";})(),(function fuck(){return \"Sx\";})(),(function fuck(){ret" ascii
    $s10 = "uck(){return \"OPz\";})(),(function fuck(){return \"IPu\";})(),(function fuck(){return \"Jo\";})(),(function fuck(){return \"RAi" ascii
    $s11 = "k(){return \"KVh\";})(),(function fuck(){return \"Vb\";})(),(function fuck(){return \"IPu\";})(),(function fuck(){return \"DRx\"" ascii
    $s12 = "{return \"Sx\";})(),(function fuck(){return \"MBg\";})(),(function fuck(){return \"Nm\";})(),(function fuck(){return \"Wo\";})()" ascii

  condition:
    (uint16(0) == 0x2f0a and (8 of them)
    ) or (all of them)
}