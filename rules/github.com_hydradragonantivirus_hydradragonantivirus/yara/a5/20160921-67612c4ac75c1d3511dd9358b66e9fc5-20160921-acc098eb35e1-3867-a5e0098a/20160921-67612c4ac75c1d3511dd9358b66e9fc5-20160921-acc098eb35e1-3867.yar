rule _20160921_67612c4ac75c1d3511dd9358b66e9fc5_20160921_acc098eb35e1_3867 {
  meta:
    description = "datamaliciousorder - from files 20160921_67612c4ac75c1d3511dd9358b66e9fc5.js, 20160921_acc098eb35e159f33783b155bb8929cb.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "fbf6986e3a8c7defa5c14d80cff4f3b3ce1db859ea94044f5d024758684178c0"
    hash2       = "1f491f3a68df5684f7bb14dc15b8f6f3dea400dde990f144e6cf0792facdba6e"

  strings:
    $s1 = "k(){return \"Ml\";})(),(function fuck(){return \"DHd\";})(),(function fuck(){return \"NKq\";})(),(function fuck(){return \"Ug\";" ascii
    $s2 = ";})(),(function fuck(){return \"YQt\";})(),(function fuck(){return \"Ve\";})(),(function fuck(){return \"IRn\";})(),(function fu" ascii
    $s3 = "return \"YAv\";})(),(function fuck(){return \"ADy\";})(),(function fuck(){return \"TTs\";})(),(function fuck(){return \"GWo\";})" ascii
    $s4 = "eturn \"MBg\";})(),(function fuck(){return \"Hs\";})(),(function fuck(){return \"YAv\";})(),(function fuck(){return \"USf\";})()" ascii
    $s5 = "uck(){return \"IRn\";})(),(function fuck(){return \"MBg\";})(),(function fuck(){return \"DWe\";})(),(function fuck(){return \"Sx" ascii
    $s6 = ",(function fuck(){return \"Dc\";})(),(function fuck(){return \"GNm\";})(),(function fuck(){return \"Pc\";})(),(function fuck(){r" ascii

  condition:
    (uint16(0) == 0x2f0a and (all of them)
    ) or (all of them)
}