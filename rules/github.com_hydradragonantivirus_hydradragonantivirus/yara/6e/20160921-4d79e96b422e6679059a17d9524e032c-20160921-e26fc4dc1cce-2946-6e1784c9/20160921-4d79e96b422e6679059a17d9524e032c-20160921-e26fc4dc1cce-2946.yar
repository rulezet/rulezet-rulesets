rule _20160921_4d79e96b422e6679059a17d9524e032c_20160921_e26fc4dc1cce_2946 {
  meta:
    description = "datamaliciousorder - from files 20160921_4d79e96b422e6679059a17d9524e032c.js, 20160921_e26fc4dc1ccef911251bba0675c76ce0.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "d5794a16a28dba8e89768fa9195da33a7e28c3da5fc73a7789e7c04395f23f06"
    hash2       = "f1074dcd9f3ae62af13634c9f88af0a235b2e315a2697fc222ce96bad51ca1a1"

  strings:
    $s1 = "rn \"IPu\";})(),(function fuck(){return \"Et\";})(),(function fuck(){return \"Xg\";})(),(function fuck(){return \"IPu\";})(),(fu" ascii
    $s2 = "eturn \"Np\";})(),(function fuck(){return \"LGo\";})(),(function fuck(){return \"RAi\";})(),(function fuck(){return \"ADy\";})()" ascii
    $s3 = "turn \"MUs\";})(),(function fuck(){return \"Vb\";})(),(function fuck(){return \"IPu\";})(),(function fuck(){return \"MBg\";})()," ascii
    $s4 = "eturn \"IPu\";})(),(function fuck(){return \"USf\";})(),(function fuck(){return \"Vb\";})(),(function fuck(){return \"Vb\";})()," ascii
    $s5 = "on fuck(){return \"MOj\";})(),(function fuck(){return \"IPu\";})(),(function fuck(){return \"Cs\";})(),(function fuck(){return " ascii
    $s6 = "ck(){return \"IPu\";})(),(function fuck(){return \"Et\";})(),(function fuck(){return \"Py\";})(),(function fuck(){return \"IPu\"" ascii
    $s7 = "ion fuck(){return \"Np\";})(),(function fuck(){return \"LGo\";})(),(function fuck(){return \"UOe\";})(),(function fuck(){return " ascii

  condition:
    (uint16(0) == 0x2f0a and (all of them)
    ) or (all of them)
}