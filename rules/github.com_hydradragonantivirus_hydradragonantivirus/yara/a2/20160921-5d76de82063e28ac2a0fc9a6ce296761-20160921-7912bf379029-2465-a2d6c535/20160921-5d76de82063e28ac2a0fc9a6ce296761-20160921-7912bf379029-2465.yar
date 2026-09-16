rule _20160921_5d76de82063e28ac2a0fc9a6ce296761_20160921_7912bf379029_2465 {
  meta:
    description = "datamaliciousorder - from files 20160921_5d76de82063e28ac2a0fc9a6ce296761.js, 20160921_7912bf3790296273bb8c94248adbbc9a.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "4e44228eb55ff969128759659f37a0c5ebdeb5fc653b3b206ba5fa42d8e30166"
    hash2       = "3bf106f8ef0e4b03e869f1cf914513f711eb52824441a1f2740f3faec2821404"

  strings:
    $s1 = "(){return \"OUx\";})(),(function f000(){return \"RPt\";})(),(function f000(){return \"Qj\";})(),(function f000(){return \"Qj\";}" ascii
    $s2 = " f000(){return \"Qz\";})(),(function f000(){return \"TKl\";})(),(function f000(){return \"XTn\";})(),(function f000(){return \"G" ascii
    $s3 = "on f000(){return \"RPt\";})(),(function f000(){return \"Qj\";})(),(function f000(){return \"Yi\";})(),(function f000(){return \"" ascii
    $s4 = "00(){return \"Qj\";})(),(function f000(){return \"KXg\";})(),(function f000(){return \"TRc\";})(),(function f000(){return \"WIj" ascii
    $s5 = "rn \"OUx\";})(),(function f000(){return \"Mu\";})(),(function f000(){return \"KXg\";})(),(function f000(){return \"Qj\";})(),(fu" ascii
    $s6 = "f000(){return \"Iq\";})(),(function f000(){return \"Kw\";})(),(function f000(){return \"OUx\";})(),(function f000(){return \"Qz" ascii
    $s7 = "unction f000(){return \"Mu\";})(),(function f000(){return \"GGn\";})(),(function f000(){return \"KXg\";})(),(function f000(){ret" ascii
    $s8 = "n \"TKl\";})(),(function f000(){return \"XTn\";})(),(function f000(){return \"XTn\";})(),(function f000(){return \"TRc\";})(),(f" ascii

  condition:
    (uint16(0) == 0x2f0a and (all of them)
    ) or (all of them)
}