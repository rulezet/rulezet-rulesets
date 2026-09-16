rule _20160921_5c25506bc44b50a0c8028dec6521139d_20160921_b6d1e9aee3a0_3818 {
  meta:
    description = "datamaliciousorder - from files 20160921_5c25506bc44b50a0c8028dec6521139d.js, 20160921_b6d1e9aee3a026c6f266b107f0b88f18.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "b6178db9a292199c6992547ad654bf7056fa7f33310f29988e468f0cad5ed707"
    hash2       = "e95dafe7c61e6b4aa30cf1d0f5e7ac22599967edab3c0a7152e74671d99054e2"

  strings:
    $s1 = ";})(),(function fuck(){return \"LGo\";})(),(function fuck(){return \"Ai\";})(),(function fuck(){return \"Hs\";})(),(function fuc" ascii
    $s2 = "tion fuck(){return \"MUs\";})(),(function fuck(){return \"MOj\";})(),(function fuck(){return \"NKq\";})(),(function fuck(){retur" ascii
    $s3 = "ck(){return \"Ai\";})(),(function fuck(){return \"IRn\";})(),(function fuck(){return \"MBg\";})(),(function fuck(){return \"Hs\"" ascii
    $s4 = "n \"IRn\";})(),(function fuck(){return \"OQr\";})(),(function fuck(){return \"Vb\";})(),(function fuck(){return \"Ai\";})(),(fun" ascii
    $s5 = "turn \"TTs\";})(),(function fuck(){return \"YQt\";})(),(function fuck(){return \"Wo0\";})(),(function fuck(){return \"Ai\";})()," ascii
    $s6 = "(),(function fuck(){return \"Zy\";})(),(function fuck(){return \"SUi\";})(),(function fuck(){return \"Hs\";})(),(function fuck()" ascii

  condition:
    (uint16(0) == 0x2f0a and (all of them)
    ) or (all of them)
}