rule _20160921_4ad5ed78dc05b02005f65ab785b9c74a_20160921_f7b964e1d5b6_3732 {
  meta:
    description = "datamaliciousorder - from files 20160921_4ad5ed78dc05b02005f65ab785b9c74a.js, 20160921_f7b964e1d5b6c5c4999da8838c5d62ca.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "7e5f9d362688f19111d3dbdf393d51e133fcc63eb7db27536cb31d1205ccc9e3"
    hash2       = "a4c4c13a87b8183a01386c2463dc595a8b36ca94eff8c78305da426f160e6427"

  strings:
    $s1 = "p\";})(),(function f000(){return \"Qj\";})(),(function f000(){return \"XTn\";})(),(function f000(){return \"TRc\";})(),(function" ascii
    $s2 = "on f000(){return \"GGn\";})(),(function f000(){return \"Go\";})(),(function f000(){return \"ZIi\";})(),(function f000(){return " ascii
    $s3 = "urn \"RPt\";})(),(function f000(){return \"TKl\";})(),(function f000(){return \"XTn\";})(),(function f000(){return \"TRc\";})()," ascii
    $s4 = "nction f000(){return \"Lo\";})(),(function f000(){return \"OUx\";})(),(function f000(){return \"PTi\";})(),(function f000(){retu" ascii
    $s5 = "ion f000(){return \"GGn\";})(),(function f000(){return \"MBb\";})(),(function f000(){return \"Yv\";})(),(function f000(){return " ascii
    $s6 = "return \"Qa\";})(),(function f000(){return \"Uo\";})(),(function f000(){return \"Oe\";})(),(function f000(){return \"Zj\";})(),(" ascii

  condition:
    (uint16(0) == 0x2f0a and (all of them)
    ) or (all of them)
}