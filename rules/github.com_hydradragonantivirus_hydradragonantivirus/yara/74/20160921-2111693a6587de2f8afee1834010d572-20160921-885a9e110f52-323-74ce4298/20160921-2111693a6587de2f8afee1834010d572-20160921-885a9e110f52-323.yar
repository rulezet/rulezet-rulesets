rule _20160921_2111693a6587de2f8afee1834010d572_20160921_885a9e110f52_323 {
  meta:
    description = "datamaliciousorder - from files 20160921_2111693a6587de2f8afee1834010d572.js, 20160921_885a9e110f52f3ca103e4718673adb3b.js, 20160921_9ab244a7866dc1a3d98006482dd7da38.js, 20160921_a05dfc337c4ada28e05759b304eef904.js, 20160921_de03e8e8d98da4b7d17147c979ce9ff8.js, 20160921_fa18251c4ecf88527d80b62724da7b36.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "afb04df96413e21fd33fbf65fafdf5fc01cc299acc2cbe099811e60500fbc6d7"
    hash2       = "a777a2e324ff6d64746b42793d888cea6f2beec30ded4165b5b13eda473e58bf"
    hash3       = "99692f93901b579e0992cf6f44c274569bb1257cf12f2eebf5baceb7cb31d6af"
    hash4       = "db6a3cf7e8281867bf38b22cce5a945336377679a1a85ee91d365e41ec94182c"
    hash5       = "aa4eb617dd497a7ea1d016d98ce4ca8e81e13b4e240c42d46d01e84e617a150b"
    hash6       = "21b811f7ccb44c8d67ee516b8cfe4393b6e248d9db38cab4200e9794e3da737f"

  strings:
    $s1  = "fuck(){return \"MBg\";})(),(function fuck(){return \"Vb\";})(),(function fuck(){return \"USf\";})(),(function fuck(){return \"PD" ascii
    $s2  = "uck(){return \"MBg\";})(),(function fuck(){return \"Vb\";})(),(function fuck(){return \"ADy\";})(),(function fuck(){return \"GNm" ascii
    $s3  = "return \"IPu\";})(),(function fuck(){return \"Vf\";})(),(function fuck(){return \"XCr\";})(),(function fuck(){return \"AUx\";})(" ascii
    $s4  = "return \"Vb\";})(),(function fuck(){return \"Cd\";})(),(function fuck(){return \"USf\";})(),(function fuck(){return \"NKq\";})()" ascii
    $s5  = "MBg\";})(),(function fuck(){return \"Vb\";})(),(function fuck(){return \"RAi\";})(),(function fuck(){return \"UOe\";})(),(functi" ascii
    $s6  = "tion fuck(){return \"USf\";})(),(function fuck(){return \"MBg\";})(),(function fuck(){return \"Vf\";})(),(function fuck(){return" ascii
    $s7  = ";})(),(function fuck(){return \"TTs\";})(),(function fuck(){return \"PDf\";})(),(function fuck(){return \"USf\";})(),(function f" ascii
    $s8  = " fuck(){return \"LGo\";})(),(function fuck(){return \"Cd\";})(),(function fuck(){return \"USf\";})(),(function fuck(){return \"I" ascii
    $s9  = "rn \"Vb\";})(),(function fuck(){return \"PDf\";})(),(function fuck(){return \"Cd\";})(),(function fuck(){return \"NKq\";})(),(fu" ascii
    $s10 = "ction fuck(){return \"UOe\";})(),(function fuck(){return \"PDf\";})(),(function fuck(){return \"IPu\";})(),(function fuck(){retu" ascii
    $s11 = "unction fuck(){return \"TTs\";})(),(function fuck(){return \"PDf\";})(),(function fuck(){return \"Cd\";})(),(function fuck(){ret" ascii
    $s12 = "urn \"IKv\";})(),(function fuck(){return \"RAi\";})(),(function fuck(){return \"LGo\";})(),(function fuck(){return \"PDf\";})()," ascii
    $s13 = "n \"Jo\";})(),(function fuck(){return \"Av\";})(),(function fuck(){return \"Cd\";})(),(function fuck(){return \"IPu\";})(),(func" ascii
    $s14 = "unction fuck(){return \"TTs\";})(),(function fuck(){return \"Np\";})(),(function fuck(){return \"UOe\";})(),(function fuck(){ret" ascii
    $s15 = "(){return \"PDf\";})(),(function fuck(){return \"RAi\";})(),(function fuck(){return \"IPu\";})(),(function fuck(){return \"IKv\"" ascii
    $s16 = "fuck(){return \"DWe\";})(),(function fuck(){return \"Ve\";})(),(function fuck(){return \"USf\";})(),(function fuck(){return \"MB" ascii
    $s17 = "unction fuck(){return \"IPu\";})(),(function fuck(){return \"Ug\";})(),(function fuck(){return \"Bz\";})(),(function fuck(){retu" ascii
    $s18 = "function fuck(){return \"LGo\";})(),(function fuck(){return \"Cd\";})(),(function fuck(){return \"GNm\";})(),(function fuck(){re" ascii
    $s19 = "),(function fuck(){return \"UOe\";})(),(function fuck(){return \"GNm\";})(),(function fuck(){return \"Cd\";})(),(function fuck()" ascii
    $s20 = "\"IPu\";})(),(function fuck(){return \"Jo\";})(),(function fuck(){return \"Za\";})(),(function fuck(){return \"Za\";})(),(functi" ascii

  condition:
    (uint16(0) == 0x2f0a and (8 of them)
    ) or (all of them)
}