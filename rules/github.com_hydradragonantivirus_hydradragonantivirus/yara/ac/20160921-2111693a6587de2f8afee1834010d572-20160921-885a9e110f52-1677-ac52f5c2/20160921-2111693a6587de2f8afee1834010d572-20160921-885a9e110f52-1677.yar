rule _20160921_2111693a6587de2f8afee1834010d572_20160921_885a9e110f52_1677 {
  meta:
    description = "datamaliciousorder - from files 20160921_2111693a6587de2f8afee1834010d572.js, 20160921_885a9e110f52f3ca103e4718673adb3b.js, 20160921_9ab244a7866dc1a3d98006482dd7da38.js, 20160921_a05dfc337c4ada28e05759b304eef904.js, 20160921_fa18251c4ecf88527d80b62724da7b36.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "afb04df96413e21fd33fbf65fafdf5fc01cc299acc2cbe099811e60500fbc6d7"
    hash2       = "a777a2e324ff6d64746b42793d888cea6f2beec30ded4165b5b13eda473e58bf"
    hash3       = "99692f93901b579e0992cf6f44c274569bb1257cf12f2eebf5baceb7cb31d6af"
    hash4       = "db6a3cf7e8281867bf38b22cce5a945336377679a1a85ee91d365e41ec94182c"
    hash5       = "21b811f7ccb44c8d67ee516b8cfe4393b6e248d9db38cab4200e9794e3da737f"

  strings:
    $s1  = "k(){return \"DRx\";})(),(function fuck(){return \"IPu\";})(),(function fuck(){return \"Zy\";})(),(function fuck(){return \"We\";" ascii
    $s2  = "n fuck(){return \"Hs\";})(),(function fuck(){return \"EHo\";})(),(function fuck(){return \"Np\";})(),(function fuck(){return \"I" ascii
    $s3  = " \"SUi\";})(),(function fuck(){return \"Cd\";})(),(function fuck(){return \"MOj\";})(),(function fuck(){return \"NKq\";})(),(fun" ascii
    $s4  = "fuck(){return \"IPu\";})(),(function fuck(){return \"Ai\";})(),(function fuck(){return \"AUx\";})(),(function fuck(){return \"Np" ascii
    $s5  = "){return \"Jo\";})(),(function fuck(){return \"Av\";})(),(function fuck(){return \"Cd\";})(),(function fuck(){return \"MBg\";})(" ascii
    $s6  = "u\";})(),(function fuck(){return \"Vf\";})(),(function fuck(){return \"EHo\";})(),(function fuck(){return \"IRn\";})(),(function" ascii
    $s7  = ")(),(function fuck(){return \"TTs\";})(),(function fuck(){return \"Hs\";})(),(function fuck(){return \"GWo\";})(),(function fuck" ascii
    $s8  = "function fuck(){return \"ADy\";})(),(function fuck(){return \"TTs\";})(),(function fuck(){return \"CCb\";})(),(function fuck(){r" ascii
    $s9  = "n fuck(){return \"XFd\";})(),(function fuck(){return \"Nm\";})(),(function fuck(){return \"QTc\";})(),(function fuck(){return \"" ascii
    $s10 = "n \"ZWu\";})(),(function fuck(){return \"AUx\";})(),(function fuck(){return \"IPu\";})(),(function fuck(){return \"DRx\";})(),(f" ascii
    $s11 = "\"Yk\";})(),(function fuck(){return \"AUx\";})(),(function fuck(){return \"LGo\";})(),(function fuck(){return \"IPu\";})(),(func" ascii

  condition:
    (uint16(0) == 0x2f0a and (8 of them)
    ) or (all of them)
}