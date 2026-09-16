rule _20160921_9ef73b9f4f78d9ac2f908b3cdd8db13d_20160921_acc098eb35e1_3102 {
  meta:
    description = "datamaliciousorder - from files 20160921_9ef73b9f4f78d9ac2f908b3cdd8db13d.js, 20160921_acc098eb35e159f33783b155bb8929cb.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "31bd1528e102f576486e80b1ead7224fc04db7a81b4fbf1ae11c4416b5e4bd57"
    hash2       = "1f491f3a68df5684f7bb14dc15b8f6f3dea400dde990f144e6cf0792facdba6e"

  strings:
    $s1 = "nction fuck(){return \"DRx\";})(),(function fuck(){return \"IPu\";})(),(function fuck(){return \"ZWu\";})(),(function fuck(){ret" ascii
    $s2 = "GNm\";})(),(function fuck(){return \"DRx\";})(),(function fuck(){return \"We\";})(),(function fuck(){return \"QTc\";})(),(functi" ascii
    $s3 = "Pu\";})(),(function fuck(){return \"YQt\";})(),(function fuck(){return \"We\";})(),(function fuck(){return \"Dc\";})(),(function" ascii
    $s4 = "(){return \"DRx\";})(),(function fuck(){return \"XCr\";})(),(function fuck(){return \"Na\";})(),(function fuck(){return \"IPu\";" ascii
    $s5 = "uck(){return \"OQr\";})(),(function fuck(){return \"Hs\";})(),(function fuck(){return \"Wo0\";})(),(function fuck(){return \"ZVi" ascii
    $s6 = "Ld\";})(),(function fuck(){return \"YAv\";})(),(function fuck(){return \"IPu\";})(),(function fuck(){return \"DRx\";})(),(functi" ascii
    $s7 = "(){return \"IPu\";})(),(function fuck(){return \"ZLd\";})(),(function fuck(){return \"Jg\";})(),(function fuck(){return \"Vb\";}" ascii

  condition:
    (uint16(0) == 0x2f0a and (all of them)
    ) or (all of them)
}