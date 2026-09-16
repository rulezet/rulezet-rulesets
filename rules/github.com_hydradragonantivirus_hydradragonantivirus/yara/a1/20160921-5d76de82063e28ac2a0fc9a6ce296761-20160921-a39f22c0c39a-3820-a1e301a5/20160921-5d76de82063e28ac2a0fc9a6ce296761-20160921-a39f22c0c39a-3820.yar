rule _20160921_5d76de82063e28ac2a0fc9a6ce296761_20160921_a39f22c0c39a_3820 {
  meta:
    description = "datamaliciousorder - from files 20160921_5d76de82063e28ac2a0fc9a6ce296761.js, 20160921_a39f22c0c39a7d5bb3c55dd00a36b5b1.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "4e44228eb55ff969128759659f37a0c5ebdeb5fc653b3b206ba5fa42d8e30166"
    hash2       = "6a56bdeaf1decad9c4fa4ee5ac7e377d80dfd12601d1317d02f12d9d9fb19646"

  strings:
    $s1 = "n \"WIj\";})(),(function f000(){return \"RPt\";})(),(function f000(){return \"KXg\";})(),(function f000(){return \"Qj\";})(),(fu" ascii
    $s2 = "ion f000(){return \"WIj\";})(),(function f000(){return \"Qj\";})(),(function f000(){return \"RPt\";})(),(function f000(){return " ascii
    $s3 = "rn \"Kw\";})(),(function f000(){return \"OUx\";})(),(function f000(){return \"Kw\";})(),(function f000(){return \"XTn\";})(),(fu" ascii
    $s4 = "turn \"GGn\";})(),(function f000(){return \"XTn\";})(),(function f000(){return \"RPt\";})(),(function f000(){return \"KXg\";})()" ascii
    $s5 = "turn \"GGn\";})(),(function f000(){return \"Lp\";})(),(function f000(){return \"Qj\";})(),(function f000(){return \"Kw\";})(),(f" ascii
    $s6 = "ion f000(){return \"Mu\";})(),(function f000(){return \"TKl\";})(),(function f000(){return \"Qj\";})(),(function f000(){return " ascii

  condition:
    (uint16(0) == 0x2f0a and (all of them)
    ) or (all of them)
}