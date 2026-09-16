rule _20160921_0a459915b243d5878c25fef831b72789_20160921_1766f5c818d6_4334 {
  meta:
    description = "datamaliciousorder - from files 20160921_0a459915b243d5878c25fef831b72789.js, 20160921_1766f5c818d6371cb36488c98158ccd2.js, 20160921_73b5a50d06622b8411077815f2717627.js, 20160921_86f41d8c83240a68770674107f15f162.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "9f8d1944044e8a67a527f50e4aeb45e9358929b0d0f7aaf1730d2782f07a09de"
    hash2       = "4d8985b767534ef1312401b6a38570477e0c87ed4ef37c945eee55179929c0a4"
    hash3       = "ff8a171dec88d707916b1928e49d84c61474fe9b0faf2916e72eadb2b404d04b"
    hash4       = "56a4c0b8742284d9e8907df1b8d73d9c73ee82bc9595e88d869c555afd77312d"

  strings:
    $s1 = "n \"GGn\";})(),(function f000(){return \"Sv\";})(),(function f000(){return \"Tb\";})(),(function f000(){return \"Oe\";})(),(func" ascii
    $s2 = "){return \"Nx\";})(),(function f000(){return \"RPt\";})(),(function f000(){return \"TRc\";})(),(function f000(){return \"Zj\";})" ascii
    $s3 = "f000(){return \"MDb\";})(),(function f000(){return \"GGn\";})(),(function f000(){return \"ZFe\";})(),(function f000(){return \"D" ascii
    $s4 = "function f000(){return \"Oh\";})(),(function f000(){return \"YTp\";})(),(function f000(){return \"Kw\";})(),(function f000(){ret" ascii
    $s5 = "nction f000(){return \"UEg\";})(),(function f000(){return \"QDg\";})(),(function f000(){return \"Sj\";})(),(function f000(){retu" ascii

  condition:
    (uint16(0) == 0x2f0a and (all of them)
    ) or (all of them)
}