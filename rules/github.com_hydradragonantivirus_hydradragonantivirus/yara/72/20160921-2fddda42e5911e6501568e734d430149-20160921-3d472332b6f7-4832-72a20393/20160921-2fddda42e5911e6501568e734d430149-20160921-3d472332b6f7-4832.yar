rule _20160921_2fddda42e5911e6501568e734d430149_20160921_3d472332b6f7_4832 {
  meta:
    description = "datamaliciousorder - from files 20160921_2fddda42e5911e6501568e734d430149.js, 20160921_3d472332b6f7d53a9f60478e1312ea58.js, 20160921_f7b964e1d5b6c5c4999da8838c5d62ca.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "39e075f0b6da6e9616ecc55632d12b76e677c40d3e27c38908b71f907b17d8e1"
    hash2       = "afa09723c03c97cb533583268f8fb586a7ccfc3438d793acc59eedb90be55b5b"
    hash3       = "a4c4c13a87b8183a01386c2463dc595a8b36ca94eff8c78305da426f160e6427"

  strings:
    $s1 = ")(),(function f000(){return \"Wy\";})(),(function f000(){return \"PTs\";})(),(function f000(){return \"Iq\";})(),(function f000(" ascii
    $s2 = "n\";})(),(function f000(){return \"Vu\";})(),(function f000(){return \"Sq\";})(),(function f000(){return \"GGn\";})(),(function " ascii
    $s3 = "f000(){return \"Vj\";})(),(function f000(){return \"Nx\";})(),(function f000(){return \"DIa\";})(),(function f000(){return \"Zj" ascii
    $s4 = "rn \"BQb\";})(),(function f000(){return \"Oe\";})(),(function f000(){return \"QDg\";})(),(function f000(){return \"DNa\";})(),(f" ascii
    $s5 = "ion f000(){return \"DYx\";})(),(function f000(){return \"Ml\";})(),(function f000(){return \"DNa\";})(),(function f000(){return " ascii

  condition:
    (uint16(0) == 0x2f0a and (all of them)
    ) or (all of them)
}