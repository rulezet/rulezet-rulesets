rule _20160921_56560f8d7ec61c150afb741a4a7975e2_20160921_885a9e110f52_5206 {
  meta:
    description = "datamaliciousorder - from files 20160921_56560f8d7ec61c150afb741a4a7975e2.js, 20160921_885a9e110f52f3ca103e4718673adb3b.js, 20160921_9ab244a7866dc1a3d98006482dd7da38.js, 20160921_ef83849d63779003debb3d7ec32b193e.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "ba922e4e746eb45b8e98a88ec3071072c0850dbd5e2a359302331e1ae65210fb"
    hash2       = "a777a2e324ff6d64746b42793d888cea6f2beec30ded4165b5b13eda473e58bf"
    hash3       = "99692f93901b579e0992cf6f44c274569bb1257cf12f2eebf5baceb7cb31d6af"
    hash4       = "8c488afd3d971ee89eb15305d884bacb01b91fa70760bea0aaf808120622dfa3"

  strings:
    $s1 = "n fuck(){return \"Jo\";})(),(function fuck(){return \"Qh\";})(),(function fuck(){return \"Fv\";})(),(function fuck(){return \"IP" ascii
    $s2 = "(function fuck(){return \"We\";})(),(function fuck(){return \"Jg\";})(),(function fuck(){return \"PDf\";})(),(function fuck(){re" ascii
    $s3 = "k(){return \"IPu\";})(),(function fuck(){return \"Ai\";})(),(function fuck(){return \"XHj\";})(),(function fuck(){return \"Na\";" ascii
    $s4 = " \"Et\";})(),(function fuck(){return \"Ve\";})(),(function fuck(){return \"IPu\";})(),(function fuck(){return \"DRx\";})(),(func" ascii
    $s5 = "eturn \"IPu\";})(),(function fuck(){return \"ZWu\";})(),(function fuck(){return \"XFd\";})(),(function fuck(){return \"Av\";})()" ascii

  condition:
    (uint16(0) == 0x2f0a and (all of them)
    ) or (all of them)
}