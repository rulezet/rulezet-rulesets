rule _20160921_23ef471e720525eb3dff80c2296d1a60_20160921_74aa1eb054c4_3536 {
  meta:
    description = "datamaliciousorder - from files 20160921_23ef471e720525eb3dff80c2296d1a60.js, 20160921_74aa1eb054c4d9cf85bcad2468e8404a.js, 20160921_b71168af39c5eec1d403d381eea7ffe1.js, 20160921_cbfbdc544b309301bc71d300d7726545.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "b0945c221a3a5ff2958847eac00c479ff3a9b1c8dd949684148aca0eeaf3afeb"
    hash2       = "74bb8f886c1de9aea157cf5ee2e1b8c02b30df1117e95e18ef3a2d5dc44277ad"
    hash3       = "c8811edeb74999e8dd226f7fa9d7963ccfc998904ecb9474d036376253dc6fde"
    hash4       = "135f44db2fcd47db2f5b9cd01f10f5c892ae119d904f5cb0ea4bbdaafba92963"

  strings:
    $s1 = " \"Do\";})(),(function f000(){return \"Do\";})(),(function f000(){return \"Do\";})(),(function f000(){return \"Zj\";})(),(functi" ascii
    $s2 = " f000(){return \"GGn\";})(),(function f000(){return \"Sj0\";})(),(function f000(){return \"WIj\";})(),(function f000(){return \"" ascii
    $s3 = "function f000(){return \"GGn\";})(),(function f000(){return \"OUx\";})(),(function f000(){return \"TRc\";})(),(function f000(){r" ascii
    $s4 = "ion f000(){return \"RPt\";})(),(function f000(){return \"Do\";})(),(function f000(){return \"Do\";})(),(function f000(){return " ascii
    $s5 = "rn \"GGn\";})(),(function f000(){return \"BIj\";})(),(function f000(){return \"Tn\";})(),(function f000(){return \"Oe\";})(),(fu" ascii
    $s6 = "\"Zj\";})(),(function f000(){return \"KZr\";})(),(function f000(){return \"Zj\";})(),(function f000(){return \"MMz\";})(),(funct" ascii

  condition:
    (uint16(0) == 0x2f0a and (all of them)
    ) or (all of them)
}