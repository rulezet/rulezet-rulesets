rule _20160921_10a3e0605b8ced0a0dee77069aa99014_20160921_5d76de82063e_4399 {
  meta:
    description = "datamaliciousorder - from files 20160921_10a3e0605b8ced0a0dee77069aa99014.js, 20160921_5d76de82063e28ac2a0fc9a6ce296761.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "462b92b513dfa104fe3c095cbf98c34389b13ed004671baf4f95430e8487a108"
    hash2       = "4e44228eb55ff969128759659f37a0c5ebdeb5fc653b3b206ba5fa42d8e30166"

  strings:
    $s1 = "\"EZu\";})(),(function f000(){return \"Yi\";})(),(function f000(){return \"OUx\";})(),(function f000(){return \"Lp\";})(),(funct" ascii
    $s2 = "nction f000(){return \"RPt\";})(),(function f000(){return \"TKl\";})(),(function f000(){return \"RPt\";})(),(function f000(){ret" ascii
    $s3 = ",(function f000(){return \"Qz\";})(),(function f000(){return \"Qj\";})(),(function f000(){return \"GGn\";})(),(function f000(){r" ascii
    $s4 = "on f000(){return \"Lp\";})(),(function f000(){return \"Kw\";})(),(function f000(){return \"Lp\";})(),(function f000(){return \"X" ascii
    $s5 = "\"Mu\";})(),(function f000(){return \"GGn\";})(),(function f000(){return \"Qj\";})(),(function f000(){return \"KXg\";})(),(funct" ascii

  condition:
    (uint16(0) == 0x2f0a and (all of them)
    ) or (all of them)
}