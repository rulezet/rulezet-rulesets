rule _20160921_b2002e7f99c6e0351a90c5fe98b8b775_20160921_d6dc24b88112_3125 {
  meta:
    description = "datamaliciousorder - from files 20160921_b2002e7f99c6e0351a90c5fe98b8b775.js, 20160921_d6dc24b88112bfdeca39a6062c7510f7.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "1e6376c7075a97cbb4e180ac5ea89ade4f5170dd182e1014b19fd2ed4aa33345"
    hash2       = "b22daaadbd25f5bd920609cbc37e7ea10c4cd99c069220697c4c5db594cffee2"

  strings:
    $s1 = "),(function f000(){return \"KXg\";})(),(function f000(){return \"Qa\";})(),(function f000(){return \"ZFe\";})(),(function f000()" ascii
    $s2 = "turn \"Qa\";})(),(function f000(){return \"Do\";})(),(function f000(){return \"TRc\";})(),(function f000(){return \"WIj\";})(),(" ascii
    $s3 = "f000(){return \"ZFe\";})(),(function f000(){return \"RPt\";})(),(function f000(){return \"Zj\";})(),(function f000(){return \"MM" ascii
    $s4 = "(function f000(){return \"GGn\";})(),(function f000(){return \"Go\";})(),(function f000(){return \"TKp\";})(),(function f000(){r" ascii
    $s5 = "00(){return \"OUx\";})(),(function f000(){return \"ZFe\";})(),(function f000(){return \"TKl\";})(),(function f000(){return \"TKl" ascii
    $s6 = "),(function f000(){return \"Qz\";})(),(function f000(){return \"ZFe\";})(),(function f000(){return \"XTn\";})(),(function f000()" ascii
    $s7 = "on f000(){return \"GGn\";})(),(function f000(){return \"Tb\";})(),(function f000(){return \"Vj\";})(),(function f000(){return \"" ascii

  condition:
    (uint16(0) == 0x2f0a and (all of them)
    ) or (all of them)
}