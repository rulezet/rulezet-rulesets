rule _20160921_18e4d81197d615e3008ec96ea25b7dc4_20160921_202394e6610d_4545 {
  meta:
    description = "datamaliciousorder - from files 20160921_18e4d81197d615e3008ec96ea25b7dc4.js, 20160921_202394e6610dfa0f27f737c781d5c579.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "4b707313cf8ee2fdf903e5516937a17e48e75059c21a08483659705a96da9670"
    hash2       = "d10df61dcb3a781b5266597c0f1a9d52066cebbebf5196ad93fd81855575ed11"

  strings:
    $s1 = "unction f000(){return \"DYx\";})(),(function f000(){return \"EZu\";})(),(function f000(){return \"Oe\";})(),(function f000(){ret" ascii
    $s2 = "\"KXg\";})(),(function f000(){return \"TRc\";})(),(function f000(){return \"QDg\";})(),(function f000(){return \"Vj\";})(),(func" ascii
    $s3 = "0(){return \"Mc\";})(),(function f000(){return \"Qj\";})(),(function f000(){return \"OMd\";})(),(function f000(){return \"GGn\";" ascii
    $s4 = ",(function f000(){return \"Oh\";})(),(function f000(){return \"Sv\";})(),(function f000(){return \"YTp\";})(),(function f000(){r" ascii
    $s5 = "000(){return \"Ml\";})(),(function f000(){return \"Wy\";})(),(function f000(){return \"DYx\";})(),(function f000(){return \"Vj\"" ascii

  condition:
    (uint16(0) == 0x2f0a and (all of them)
    ) or (all of them)
}