rule _20160921_22314dccf19b7c672f3deae2294f4b16_20160921_4b801afbcd98_4708 {
  meta:
    description = "datamaliciousorder - from files 20160921_22314dccf19b7c672f3deae2294f4b16.js, 20160921_4b801afbcd9818be02d65ee0ac30ad19.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "9361b0d332b84592c527454959eb22d4191bb17c4d1acc962c192e90e96fc83e"
    hash2       = "f85dba2504097034fa23d87391ecdaf7fe5f29824616a8d91d353284964bfac1"

  strings:
    $s1 = "\"Yi\";})(),(function f000(){return \"OUx\";})(),(function f000(){return \"XTn\";})(),(function f000(){return \"XTn\";})(),(func" ascii
    $s2 = "unction f000(){return \"OUx\";})(),(function f000(){return \"TRc\";})(),(function f000(){return \"Zj\";})(),(function f000(){ret" ascii
    $s3 = "tion f000(){return \"KXg\";})(),(function f000(){return \"Yi\";})(),(function f000(){return \"TKl\";})(),(function f000(){return" ascii
    $s4 = "n \"BIj\";})(),(function f000(){return \"Tn\";})(),(function f000(){return \"Oe\";})(),(function f000(){return \"Wy\";})(),(func" ascii
    $s5 = "f000(){return \"Sj0\";})(),(function f000(){return \"WIj\";})(),(function f000(){return \"GGn\";})(),(function f000(){return \"R" ascii

  condition:
    (uint16(0) == 0x2f0a and (all of them)
    ) or (all of them)
}