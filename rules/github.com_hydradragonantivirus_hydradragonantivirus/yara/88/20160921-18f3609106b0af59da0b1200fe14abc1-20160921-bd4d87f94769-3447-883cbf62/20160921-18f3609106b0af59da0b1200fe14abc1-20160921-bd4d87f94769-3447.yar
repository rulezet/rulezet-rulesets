rule _20160921_18f3609106b0af59da0b1200fe14abc1_20160921_bd4d87f94769_3447 {
  meta:
    description = "datamaliciousorder - from files 20160921_18f3609106b0af59da0b1200fe14abc1.js, 20160921_bd4d87f94769a02253ed6ac2e747557f.js, 20160921_dcd6ef8585af301daafce3419ba14724.js, 20160921_e4c63c3b699efd2f5fe2739b016a938a.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "95fb9e6292746461417b0e539747d500c780ad17cb775a9db031f77eaa53a3e2"
    hash2       = "de567d209b0d4353173c2f3ae63037edd6f5695cc5edcdba1dba29b422d963ac"
    hash3       = "599a5b97cea2145a98305cb09031a146a6d64c54509328df8783368c3a3ba008"
    hash4       = "9d5d6c2986818649619806d890aad49cda8d0da47fe67f38388e5441a53382a0"

  strings:
    $s1 = "eturn \"PDf\";})(),(function fuck(){return \"DRx\";})(),(function fuck(){return \"Ot\";})(),(function fuck(){return \"Ai\";})()," ascii
    $s2 = "tion fuck(){return \"IPu\";})(),(function fuck(){return \"Hs\";})(),(function fuck(){return \"Jh\";})(),(function fuck(){return " ascii
    $s3 = "{return \"Na\";})(),(function fuck(){return \"UOe\";})(),(function fuck(){return \"IPu\";})(),(function fuck(){return \"DRx\";})" ascii
    $s4 = "})(),(function fuck(){return \"DRx\";})(),(function fuck(){return \"XFd\";})(),(function fuck(){return \"MUs\";})(),(function fu" ascii
    $s5 = "n fuck(){return \"Na\";})(),(function fuck(){return \"DRx\";})(),(function fuck(){return \"Oh\";})(),(function fuck(){return \"V" ascii
    $s6 = ",(function fuck(){return \"MUs\";})(),(function fuck(){return \"DRx\";})(),(function fuck(){return \"YQt\";})(),(function fuck()" ascii

  condition:
    (uint16(0) == 0x2f0a and (all of them)
    ) or (all of them)
}