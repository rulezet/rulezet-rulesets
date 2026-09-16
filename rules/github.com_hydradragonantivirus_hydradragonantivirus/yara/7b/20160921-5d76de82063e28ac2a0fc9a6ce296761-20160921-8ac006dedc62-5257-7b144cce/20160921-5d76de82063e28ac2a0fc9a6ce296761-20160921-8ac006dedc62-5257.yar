rule _20160921_5d76de82063e28ac2a0fc9a6ce296761_20160921_8ac006dedc62_5257 {
  meta:
    description = "datamaliciousorder - from files 20160921_5d76de82063e28ac2a0fc9a6ce296761.js, 20160921_8ac006dedc6205f05757feeef6cd894a.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "4e44228eb55ff969128759659f37a0c5ebdeb5fc653b3b206ba5fa42d8e30166"
    hash2       = "00e17d6bd534b2582622ec06dbd3fa43882b34044fc369b6707b8d580a7cc293"

  strings:
    $s1 = "eturn \"Mc\";})(),(function f000(){return \"Wy\";})(),(function f000(){return \"OUx\";})(),(function f000(){return \"Um\";})(),(" ascii
    $s2 = "rn \"Tb\";})(),(function f000(){return \"DAp\";})(),(function f000(){return \"TKp\";})(),(function f000(){return \"Lp\";})(),(fu" ascii
    $s3 = " f000(){return \"GGn\";})(),(function f000(){return \"HJm\";})(),(function f000(){return \"Mc\";})(),(function f000(){return \"X" ascii
    $s4 = " f000(){return \"KDh\";})(),(function f000(){return \"RVb\";})(),(function f000(){return \"GGn\";})(),(function f000(){return \"" ascii
    $s5 = "rn \"IPu\";})(),(function f000(){return \"XTn\";})(),(function f000(){return \"GGn\";})(),(function f000(){return \"MDb\";})(),(" ascii

  condition:
    (uint16(0) == 0x2f0a and (all of them)
    ) or (all of them)
}