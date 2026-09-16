rule _20160921_3ca43590701fad2cb827b5edf3989d00_20160921_7a3c07ee9b5a_5004 {
  meta:
    description = "datamaliciousorder - from files 20160921_3ca43590701fad2cb827b5edf3989d00.js, 20160921_7a3c07ee9b5aeabadf2f6cce951819f0.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "ef7c5701a8646e7803463e9a01e4f2e45cd535f2ed7174e97abde991a779b665"
    hash2       = "f3f9ad4055c2ff243fcdf662544ac5eff6ef170765938a028b9c6e0029fcb2a7"

  strings:
    $s1 = "(function f000(){return \"KXg\";})(),(function f000(){return \"RPt\";})(),(function f000(){return \"ZFe\";})(),(function f000(){" ascii
    $s2 = "rn \"DIa\";})(),(function f000(){return \"GGn\";})(),(function f000(){return \"BIj\";})(),(function f000(){return \"Tn\";})(),(f" ascii
    $s3 = "\"TRc\";})(),(function f000(){return \"Zj\";})(),(function f000(){return \"KZr\";})(),(function f000(){return \"Zj\";})(),(funct" ascii
    $s4 = "function f000(){return \"TKp\";})(),(function f000(){return \"GGn\";})(),(function f000(){return \"OUx\";})(),(function f000(){r" ascii
    $s5 = "n f000(){return \"Sq\";})(),(function f000(){return \"GGn\";})(),(function f000(){return \"Sj0\";})(),(function f000(){return \"" ascii

  condition:
    (uint16(0) == 0x2f0a and (all of them)
    ) or (all of them)
}