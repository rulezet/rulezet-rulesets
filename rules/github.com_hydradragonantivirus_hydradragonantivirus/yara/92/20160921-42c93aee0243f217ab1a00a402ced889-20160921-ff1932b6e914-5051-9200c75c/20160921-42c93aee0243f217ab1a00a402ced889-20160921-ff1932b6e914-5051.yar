rule _20160921_42c93aee0243f217ab1a00a402ced889_20160921_ff1932b6e914_5051 {
  meta:
    description = "datamaliciousorder - from files 20160921_42c93aee0243f217ab1a00a402ced889.js, 20160921_ff1932b6e91481dd80ff6251296b57fe.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "740dfd31653bea8abfef6b3038aec0b854878d45a8de4bde67cdb9124c6bbea0"
    hash2       = "07e5271d8517f89575dc2737fae5e8da89c7f2f25cd40c68e183d826da6b2bf0"

  strings:
    $s1 = ")(),(function f000(){return \"GGn\";})(),(function f000(){return \"SEo\";})(),(function f000(){return \"Yz\";})(),(function f000" ascii
    $s2 = "turn \"Wh\";})(),(function f000(){return \"Ut\";})(),(function f000(){return \"GGn\";})(),(function f000(){return \"Sj\";})(),(f" ascii
    $s3 = "{return \"ZIi\";})(),(function f000(){return \"TRc\";})(),(function f000(){return \"WIj\";})(),(function f000(){return \"Vu\";})" ascii
    $s4 = ")(),(function f000(){return \"EZu\";})(),(function f000(){return \"MJq\";})(),(function f000(){return \"GGn\";})(),(function f00" ascii
    $s5 = "nction f000(){return \"OUx\";})(),(function f000(){return \"BMj\";})(),(function f000(){return \"Yz\";})(),(function f000(){retu" ascii

  condition:
    (uint16(0) == 0x2f0a and (all of them)
    ) or (all of them)
}