rule _20160921_4cbbeff2b84f01cc3ab55f4eb29babb2_20160921_b714100d69b9_5134 {
  meta:
    description = "datamaliciousorder - from files 20160921_4cbbeff2b84f01cc3ab55f4eb29babb2.js, 20160921_b714100d69b955de920a302ff8bef7db.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "698c46439ef391a98b04ac1a2759ff8a84b30a9c444a7575c5290eb0aa4b66b9"
    hash2       = "fc43d54db3c24d6f7ce2d47a45ffcd0768d5cfe90e405322e477be98fe4a8170"

  strings:
    $s1 = "tion fuck(){return \"RAi\";})(),(function fuck(){return \"Hs\";})(),(function fuck(){return \"ADy\";})(),(function fuck(){return" ascii
    $s2 = "eturn \"RAi\";})(),(function fuck(){return \"Np\";})(),(function fuck(){return \"Jo\";})(),(function fuck(){return \"NKq\";})()," ascii
    $s3 = "rn \"CTm\";})(),(function fuck(){return \"CTm\";})(),(function fuck(){return \"CTm\";})(),(function fuck(){return \"GNm\";})(),(" ascii
    $s4 = "n \"ADy\";})(),(function fuck(){return \"Hs\";})(),(function fuck(){return \"Np\";})(),(function fuck(){return \"IPu\";})(),(fun" ascii
    $s5 = "ck(){return \"IKv\";})(),(function fuck(){return \"IPu\";})(),(function fuck(){return \"Hs\";})(),(function fuck(){return \"UOe" ascii

  condition:
    (uint16(0) == 0x2f0a and (all of them)
    ) or (all of them)
}