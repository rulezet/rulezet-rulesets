rule _20160921_5cc1e2fc6d6fe845510388bfa2dd1826_20160921_ede755ec6df0_5250 {
  meta:
    description = "datamaliciousorder - from files 20160921_5cc1e2fc6d6fe845510388bfa2dd1826.js, 20160921_ede755ec6df0951d79fb3f792a6b28b8.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "8517cbcc9f90e7835f4bbbef31cd3779f0298cca7076dd98e48fb69d359f4820"
    hash2       = "24831eade0fe1d3e87c174bc2c80b113a66f4b5da6235749feba09a377913e7a"

  strings:
    $s1 = "\"Xw\";})(),(function fuck(){return \"Qh\";})(),(function fuck(){return \"Qh\";})(),(function fuck(){return \"Xw\";})(),(functio" ascii
    $s2 = "ion fuck(){return \"AUx\";})(),(function fuck(){return \"RAi\";})(),(function fuck(){return \"UOe\";})(),(function fuck(){return" ascii
    $s3 = "Pu\";})(),(function fuck(){return \"Wo0\";})(),(function fuck(){return \"Ot\";})(),(function fuck(){return \"Py\";})(),(function" ascii
    $s4 = "Xg\";})(),(function fuck(){return \"Ug\";})(),(function fuck(){return \"Bz\";})(),(function fuck(){return \"Tv\";})(),(function " ascii
    $s5 = "ion fuck(){return \"USf\";})(),(function fuck(){return \"TTs\";})(),(function fuck(){return \"Vb\";})(),(function fuck(){return " ascii

  condition:
    (uint16(0) == 0x2f0a and (all of them)
    ) or (all of them)
}