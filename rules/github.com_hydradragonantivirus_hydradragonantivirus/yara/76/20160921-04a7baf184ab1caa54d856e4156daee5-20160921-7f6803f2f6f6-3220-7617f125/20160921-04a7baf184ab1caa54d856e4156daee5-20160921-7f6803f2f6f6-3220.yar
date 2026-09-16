rule _20160921_04a7baf184ab1caa54d856e4156daee5_20160921_7f6803f2f6f6_3220 {
  meta:
    description = "datamaliciousorder - from files 20160921_04a7baf184ab1caa54d856e4156daee5.js, 20160921_7f6803f2f6f680d96e6355ff22eeb754.js, 20160921_acc098eb35e159f33783b155bb8929cb.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "436cacbd20422493740457b774290fc75ea097813018720a8afa8162bb912052"
    hash2       = "90a92dcfba596004523ed3fa83de824553929a4a3723ce68cfae6d2394ad8394"
    hash3       = "1f491f3a68df5684f7bb14dc15b8f6f3dea400dde990f144e6cf0792facdba6e"

  strings:
    $s1 = "unction fuck(){return \"Hs\";})(),(function fuck(){return \"Jh\";})(),(function fuck(){return \"ADy\";})(),(function fuck(){retu" ascii
    $s2 = "ion fuck(){return \"DRx\";})(),(function fuck(){return \"Oh\";})(),(function fuck(){return \"Vf\";})(),(function fuck(){return " ascii
    $s3 = "x\";})(),(function fuck(){return \"XFd\";})(),(function fuck(){return \"MUs\";})(),(function fuck(){return \"PDf\";})(),(functio" ascii
    $s4 = ")(),(function fuck(){return \"DRx\";})(),(function fuck(){return \"YQt\";})(),(function fuck(){return \"Jg\";})(),(function fuck" ascii
    $s5 = "fuck(){return \"Za\";})(),(function fuck(){return \"IPu\";})(),(function fuck(){return \"XFd\";})(),(function fuck(){return \"ZW" ascii
    $s6 = "){return \"DRx\";})(),(function fuck(){return \"Ot\";})(),(function fuck(){return \"Ai\";})(),(function fuck(){return \"Na\";})(" ascii

  condition:
    (uint16(0) == 0x2f0a and (all of them)
    ) or (all of them)
}