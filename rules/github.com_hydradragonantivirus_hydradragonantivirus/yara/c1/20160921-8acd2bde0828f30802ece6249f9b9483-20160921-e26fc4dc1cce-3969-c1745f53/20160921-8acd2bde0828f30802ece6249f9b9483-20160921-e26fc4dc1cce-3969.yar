rule _20160921_8acd2bde0828f30802ece6249f9b9483_20160921_e26fc4dc1cce_3969 {
  meta:
    description = "datamaliciousorder - from files 20160921_8acd2bde0828f30802ece6249f9b9483.js, 20160921_e26fc4dc1ccef911251bba0675c76ce0.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "9cf59fc7ffd1ec7428d01db709ab365cf4dfe41d386ebb308b8bad860ff941b1"
    hash2       = "f1074dcd9f3ae62af13634c9f88af0a235b2e315a2697fc222ce96bad51ca1a1"

  strings:
    $s1 = "ion fuck(){return \"MBg\";})(),(function fuck(){return \"Vf\";})(),(function fuck(){return \"Ai\";})(),(function fuck(){return " ascii
    $s2 = "on fuck(){return \"USf\";})(),(function fuck(){return \"UOe\";})(),(function fuck(){return \"Hs\";})(),(function fuck(){return " ascii
    $s3 = "eturn \"Vb\";})(),(function fuck(){return \"RAi\";})(),(function fuck(){return \"Jo\";})(),(function fuck(){return \"IRn\";})()," ascii
    $s4 = "XFd\";})(),(function fuck(){return \"Na\";})(),(function fuck(){return \"IPu\";})(),(function fuck(){return \"DRx\";})(),(functi" ascii
    $s5 = "){return \"Za\";})(),(function fuck(){return \"IPu\";})(),(function fuck(){return \"Qh\";})(),(function fuck(){return \"Mw\";})(" ascii
    $s6 = "b\";})(),(function fuck(){return \"RAi\";})(),(function fuck(){return \"USf\";})(),(function fuck(){return \"IRn\";})(),(functio" ascii

  condition:
    (uint16(0) == 0x2f0a and (all of them)
    ) or (all of them)
}