rule _20160921_3bd7e22bf0147340b20eeb7a825cb9a1_20160921_fa18251c4ecf_4997 {
  meta:
    description = "datamaliciousorder - from files 20160921_3bd7e22bf0147340b20eeb7a825cb9a1.js, 20160921_fa18251c4ecf88527d80b62724da7b36.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "fabcf64721727f8848bd26426a6a8b0fdf115e6416d2ce71dfa09efadb821690"
    hash2       = "21b811f7ccb44c8d67ee516b8cfe4393b6e248d9db38cab4200e9794e3da737f"

  strings:
    $s1 = "(function fuck(){return \"DHd\";})(),(function fuck(){return \"Ar\";})(),(function fuck(){return \"Xw\";})(),(function fuck(){re" ascii
    $s2 = "),(function fuck(){return \"XFd\";})(),(function fuck(){return \"Yk\";})(),(function fuck(){return \"ZVi\";})(),(function fuck()" ascii
    $s3 = "),(function fuck(){return \"KVh\";})(),(function fuck(){return \"Cd\";})(),(function fuck(){return \"IPu\";})(),(function fuck()" ascii
    $s4 = "uck(){return \"Hs\";})(),(function fuck(){return \"Jh\";})(),(function fuck(){return \"ADy\";})(),(function fuck(){return \"IPu" ascii
    $s5 = "n \"DRx\";})(),(function fuck(){return \"IPu\";})(),(function fuck(){return \"Wo0\";})(),(function fuck(){return \"SUi\";})(),(f" ascii

  condition:
    (uint16(0) == 0x2f0a and (all of them)
    ) or (all of them)
}