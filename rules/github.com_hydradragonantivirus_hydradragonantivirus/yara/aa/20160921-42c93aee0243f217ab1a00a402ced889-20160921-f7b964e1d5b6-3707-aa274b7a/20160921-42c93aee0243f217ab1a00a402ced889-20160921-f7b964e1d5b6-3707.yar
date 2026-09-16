rule _20160921_42c93aee0243f217ab1a00a402ced889_20160921_f7b964e1d5b6_3707 {
  meta:
    description = "datamaliciousorder - from files 20160921_42c93aee0243f217ab1a00a402ced889.js, 20160921_f7b964e1d5b6c5c4999da8838c5d62ca.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "740dfd31653bea8abfef6b3038aec0b854878d45a8de4bde67cdb9124c6bbea0"
    hash2       = "a4c4c13a87b8183a01386c2463dc595a8b36ca94eff8c78305da426f160e6427"

  strings:
    $s1 = ";})(),(function f000(){return \"Mu\";})(),(function f000(){return \"Yi\";})(),(function f000(){return \"Qz\";})(),(function f000" ascii
    $s2 = "urn \"TKl\";})(),(function f000(){return \"Qz\";})(),(function f000(){return \"GGn\";})(),(function f000(){return \"MDb\";})(),(" ascii
    $s3 = " \"WIj\";})(),(function f000(){return \"WIj\";})(),(function f000(){return \"GGn\";})(),(function f000(){return \"Uo\";})(),(fun" ascii
    $s4 = " f000(){return \"GGn\";})(),(function f000(){return \"Yi\";})(),(function f000(){return \"Qz\";})(),(function f000(){return \"TK" ascii
    $s5 = "(function f000(){return \"Tn\";})(),(function f000(){return \"Mt\";})(),(function f000(){return \"MMz\";})(),(function f000(){re" ascii
    $s6 = "tion f000(){return \"Sq\";})(),(function f000(){return \"GGn\";})(),(function f000(){return \"QDg\";})(),(function f000(){return" ascii

  condition:
    (uint16(0) == 0x2f0a and (all of them)
    ) or (all of them)
}