rule _20160921_8ac006dedc6205f05757feeef6cd894a_20160921_a1cbb43a1e22_5515 {
  meta:
    description = "datamaliciousorder - from files 20160921_8ac006dedc6205f05757feeef6cd894a.js, 20160921_a1cbb43a1e22a4b1fd63ee1a724173eb.js, 20160921_da7f7f057c35b886425ec822f654da90.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "00e17d6bd534b2582622ec06dbd3fa43882b34044fc369b6707b8d580a7cc293"
    hash2       = "4154e4928eccd35fa0d42dbefe4a742700d77124216f8b5756b8ef63634071d3"
    hash3       = "b6935463e925cb13fc2413b3d7559cf8e9f5072c15dc73075977046a3e27e417"

  strings:
    $s1 = "n \"DYx\";})(),(function f000(){return \"MJq\";})(),(function f000(){return \"QDg\";})(),(function f000(){return \"Oh\";})(),(fu" ascii
    $s2 = "function f000(){return \"GGn\";})(),(function f000(){return \"Vu\";})(),(function f000(){return \"YTp\";})(),(function f000(){re" ascii
    $s3 = "){return \"ZIi\";})(),(function f000(){return \"Oe\";})(),(function f000(){return \"DIa\";})(),(function f000(){return \"Zj\";})" ascii
    $s4 = "Rc\";})(),(function f000(){return \"OMd\";})(),(function f000(){return \"GGn\";})(),(function f000(){return \"Uo\";})(),(functio" ascii
    $s5 = "turn \"Tn\";})(),(function f000(){return \"GGn\";})(),(function f000(){return \"DNa\";})(),(function f000(){return \"Tn\";})(),(" ascii

  condition:
    (uint16(0) == 0x2f0a and (all of them)
    ) or (all of them)
}