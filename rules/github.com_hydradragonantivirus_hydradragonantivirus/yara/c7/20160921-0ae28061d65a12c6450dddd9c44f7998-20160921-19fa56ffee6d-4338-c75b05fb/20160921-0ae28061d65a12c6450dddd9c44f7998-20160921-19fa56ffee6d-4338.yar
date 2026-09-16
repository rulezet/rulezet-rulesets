rule _20160921_0ae28061d65a12c6450dddd9c44f7998_20160921_19fa56ffee6d_4338 {
  meta:
    description = "datamaliciousorder - from files 20160921_0ae28061d65a12c6450dddd9c44f7998.js, 20160921_19fa56ffee6d867aeed604f46a4d4fe9.js, 20160921_38347709a1c3747cfb23ae60221ea7bf.js, 20160921_5c9dd9a0e8a8b3e5e8713af8aeaa5d59.js, 20160921_eb528bac8085eeec9ca6760c41b0a818.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "2262aefc89b27a9a5b4507f43a6978eafd72ba25a305a11cdeb589d958f0e0a6"
    hash2       = "988e83dedf7c32629210ef0407bb0e576898ac66d605c942d70e189051f472fd"
    hash3       = "39473c48023f5000ce36bdc645860556dc6b5f3b0022f86190a49370f4633bbc"
    hash4       = "415a66b711143ada4e334e2da2ea19ca0e94ec191118672a58fa21828a1cd877"
    hash5       = "cde7bce07f038dbcc12ab3207be0245adc184f6540d425dd1ec837861c3e4440"

  strings:
    $s1 = "(){return \"Za\";})(),(function fuck(){return \"IPu\";})(),(function fuck(){return \"Wo\";})(),(function fuck(){return \"PDf\";}" ascii
    $s2 = "rn \"Ai\";})(),(function fuck(){return \"FJs\";})(),(function fuck(){return \"IPu\";})(),(function fuck(){return \"DRx\";})(),(f" ascii
    $s3 = "(){return \"USf\";})(),(function fuck(){return \"TTs\";})(),(function fuck(){return \"LGo\";})(),(function fuck(){return \"YQt\"" ascii
    $s4 = "fuck(){return \"IPu\";})(),(function fuck(){return \"Jo\";})(),(function fuck(){return \"XCr\";})(),(function fuck(){return \"MU" ascii
    $s5 = "uck(){return \"DRx\";})(),(function fuck(){return \"IPu\";})(),(function fuck(){return \"ZLd\";})(),(function fuck(){return \"EH" ascii

  condition:
    (uint16(0) == 0x2f0a and (all of them)
    ) or (all of them)
}