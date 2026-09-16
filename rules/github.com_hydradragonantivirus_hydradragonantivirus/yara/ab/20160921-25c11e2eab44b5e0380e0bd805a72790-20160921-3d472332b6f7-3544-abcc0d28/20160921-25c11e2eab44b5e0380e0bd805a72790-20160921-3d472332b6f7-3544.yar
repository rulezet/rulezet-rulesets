rule _20160921_25c11e2eab44b5e0380e0bd805a72790_20160921_3d472332b6f7_3544 {
  meta:
    description = "datamaliciousorder - from files 20160921_25c11e2eab44b5e0380e0bd805a72790.js, 20160921_3d472332b6f7d53a9f60478e1312ea58.js, 20160921_8ac006dedc6205f05757feeef6cd894a.js, 20160921_9ed8ba5d12b4be06b54bbeb7c9325180.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "912d9aec3079fb6a2e4f83d3826286707a52a653de6ec6eede9711d5b416a790"
    hash2       = "afa09723c03c97cb533583268f8fb586a7ccfc3438d793acc59eedb90be55b5b"
    hash3       = "00e17d6bd534b2582622ec06dbd3fa43882b34044fc369b6707b8d580a7cc293"
    hash4       = "19b8471b5bf67286e6bfe340e23abef1def848daa18c886f2eddc2eeaa160df7"

  strings:
    $s1 = "000(){return \"TRc\";})(),(function f000(){return \"WIj\";})(),(function f000(){return \"Kw\";})(),(function f000(){return \"Yi" ascii
    $s2 = "on f000(){return \"Qz\";})(),(function f000(){return \"Lp\";})(),(function f000(){return \"Lp\";})(),(function f000(){return \"G" ascii
    $s3 = "u\";})(),(function f000(){return \"GGn\";})(),(function f000(){return \"Lp\";})(),(function f000(){return \"Lp\";})(),(function " ascii
    $s4 = "rn \"Qj\";})(),(function f000(){return \"Kw\";})(),(function f000(){return \"XTn\";})(),(function f000(){return \"Zj\";})(),(fun" ascii
    $s5 = "function f000(){return \"Kw\";})(),(function f000(){return \"Kw\";})(),(function f000(){return \"GGn\";})(),(function f000(){ret" ascii
    $s6 = "00(){return \"XTn\";})(),(function f000(){return \"Lp\";})(),(function f000(){return \"Kw\";})(),(function f000(){return \"Zj\";" ascii

  condition:
    (uint16(0) == 0x2f0a and (all of them)
    ) or (all of them)
}