rule _20160921_6f8e01604e95009c9405a4a9c31cc901_20160921_85f2776f4fe6_5384 {
  meta:
    description = "datamaliciousorder - from files 20160921_6f8e01604e95009c9405a4a9c31cc901.js, 20160921_85f2776f4fe640d2373f51ddbc697659.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "5324b4f5c36c3ebb1567659beec8a89d0c1c954daf56a6131f3aebe46384317b"
    hash2       = "0604503e68d6aa73ca3bbdb29b958ea47ad4c81b2f77ad9db2b0e8467b1c870d"

  strings:
    $s1 = ",(function fuck(){return \"TTs\";})(),(function fuck(){return \"Hs\";})(),(function fuck(){return \"USf\";})(),(function fuck(){" ascii
    $s2 = "tion fuck(){return \"OQr\";})(),(function fuck(){return \"Qh\";})(),(function fuck(){return \"PDf\";})(),(function fuck(){return" ascii
    $s3 = "on fuck(){return \"Za\";})(),(function fuck(){return \"IPu\";})(),(function fuck(){return \"Ai\";})(),(function fuck(){return \"" ascii
    $s4 = "n \"Vb\";})(),(function fuck(){return \"IRn\";})(),(function fuck(){return \"MBg\";})(),(function fuck(){return \"Hs\";})(),(fun" ascii
    $s5 = "ck(){return \"Vb\";})(),(function fuck(){return \"ADy\";})(),(function fuck(){return \"Np\";})(),(function fuck(){return \"IRn\"" ascii

  condition:
    (uint16(0) == 0x2f0a and (all of them)
    ) or (all of them)
}