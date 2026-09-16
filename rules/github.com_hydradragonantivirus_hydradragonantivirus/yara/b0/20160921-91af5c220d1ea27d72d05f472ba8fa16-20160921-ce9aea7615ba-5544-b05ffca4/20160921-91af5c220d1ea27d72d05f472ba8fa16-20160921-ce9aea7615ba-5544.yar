rule _20160921_91af5c220d1ea27d72d05f472ba8fa16_20160921_ce9aea7615ba_5544 {
  meta:
    description = "datamaliciousorder - from files 20160921_91af5c220d1ea27d72d05f472ba8fa16.js, 20160921_ce9aea7615ba4a71719a9c0d7f838fc1.js, 20160921_ee80dc6199fa2bd2aea50402a233f984.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "d8a5c3b8bd7307238c3f0a133635143674d5db84b7c5615a145a8bea310c68de"
    hash2       = "1dfc225800b3b802cbdd9312a3198f5eb4bbcdb06d5f9ffd026bb3fb4f5cf4e6"
    hash3       = "b51d9165093e08385081a749ef6331a3556fe2739b6c8f85b62e7f6ec1b4f662"

  strings:
    $s1 = " fuck(){return \"LGo\";})(),(function fuck(){return \"Hs\";})(),(function fuck(){return \"Hs\";})(),(function fuck(){return \"Hs" ascii
    $s2 = "(){return \"FJs\";})(),(function fuck(){return \"Fv\";})(),(function fuck(){return \"OQr\";})(),(function fuck(){return \"Nm\";}" ascii
    $s3 = "ction fuck(){return \"Yk\";})(),(function fuck(){return \"Wo0\";})(),(function fuck(){return \"IPu\";})(),(function fuck(){retur" ascii
    $s4 = "\"DRx\";})(),(function fuck(){return \"IPu\";})(),(function fuck(){return \"ZWu\";})(),(function fuck(){return \"Wo0\";})(),(fun" ascii
    $s5 = "(function fuck(){return \"Hs\";})(),(function fuck(){return \"IPu\";})(),(function fuck(){return \"Cs\";})(),(function fuck(){re" ascii

  condition:
    (uint16(0) == 0x2f0a and (all of them)
    ) or (all of them)
}