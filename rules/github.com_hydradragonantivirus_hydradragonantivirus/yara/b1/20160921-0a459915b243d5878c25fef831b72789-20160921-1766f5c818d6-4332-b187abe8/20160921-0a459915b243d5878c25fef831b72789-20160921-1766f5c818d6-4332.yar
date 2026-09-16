rule _20160921_0a459915b243d5878c25fef831b72789_20160921_1766f5c818d6_4332 {
  meta:
    description = "datamaliciousorder - from files 20160921_0a459915b243d5878c25fef831b72789.js, 20160921_1766f5c818d6371cb36488c98158ccd2.js, 20160921_66566a9bbc7830091a244fa6674b709b.js, 20160921_73b5a50d06622b8411077815f2717627.js, 20160921_86f41d8c83240a68770674107f15f162.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "9f8d1944044e8a67a527f50e4aeb45e9358929b0d0f7aaf1730d2782f07a09de"
    hash2       = "4d8985b767534ef1312401b6a38570477e0c87ed4ef37c945eee55179929c0a4"
    hash3       = "154f7ca38a058d2590f40ec43ada530305244e5c7e86bbedd19aa9c0e1ca02aa"
    hash4       = "ff8a171dec88d707916b1928e49d84c61474fe9b0faf2916e72eadb2b404d04b"
    hash5       = "56a4c0b8742284d9e8907df1b8d73d9c73ee82bc9595e88d869c555afd77312d"

  strings:
    $s1 = "eturn \"Mu\";})(),(function f000(){return \"GGn\";})(),(function f000(){return \"Qj\";})(),(function f000(){return \"XTn\";})()," ascii
    $s2 = "00(){return \"TKl\";})(),(function f000(){return \"RPt\";})(),(function f000(){return \"Qj\";})(),(function f000(){return \"Yi\"" ascii
    $s3 = "n f000(){return \"TKl\";})(),(function f000(){return \"TKl\";})(),(function f000(){return \"TRc\";})(),(function f000(){return " ascii
    $s4 = "n \"TRc\";})(),(function f000(){return \"Wh\";})(),(function f000(){return \"QDg\";})(),(function f000(){return \"Yi\";})(),(fun" ascii
    $s5 = "tion f000(){return \"UEg\";})(),(function f000(){return \"OUx\";})(),(function f000(){return \"Qj\";})(),(function f000(){return" ascii

  condition:
    (uint16(0) == 0x2f0a and (all of them)
    ) or (all of them)
}