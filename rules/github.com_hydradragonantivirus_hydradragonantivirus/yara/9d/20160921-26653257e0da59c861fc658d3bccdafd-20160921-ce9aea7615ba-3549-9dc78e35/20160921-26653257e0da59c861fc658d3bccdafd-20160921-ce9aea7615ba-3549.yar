rule _20160921_26653257e0da59c861fc658d3bccdafd_20160921_ce9aea7615ba_3549 {
  meta:
    description = "datamaliciousorder - from files 20160921_26653257e0da59c861fc658d3bccdafd.js, 20160921_ce9aea7615ba4a71719a9c0d7f838fc1.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "1dff3cae9c135714cad3879ac1ef904841ec9264e3448106fbedd3b57ca11e97"
    hash2       = "1dfc225800b3b802cbdd9312a3198f5eb4bbcdb06d5f9ffd026bb3fb4f5cf4e6"

  strings:
    $s1 = "(),(function fuck(){return \"ADy\";})(),(function fuck(){return \"MOj\";})(),(function fuck(){return \"GNm\";})(),(function fuck" ascii
    $s2 = "nction fuck(){return \"USf\";})(),(function fuck(){return \"TTs\";})(),(function fuck(){return \"Jo\";})(),(function fuck(){retu" ascii
    $s3 = "),(function fuck(){return \"IPu\";})(),(function fuck(){return \"Hs\";})(),(function fuck(){return \"USf\";})(),(function fuck()" ascii
    $s4 = "unction fuck(){return \"Jh\";})(),(function fuck(){return \"USf\";})(),(function fuck(){return \"TTs\";})(),(function fuck(){ret" ascii
    $s5 = "e\";})(),(function fuck(){return \"Hs\";})(),(function fuck(){return \"USf\";})(),(function fuck(){return \"IPu\";})(),(function" ascii
    $s6 = "return \"Ar\";})(),(function fuck(){return \"Xg\";})(),(function fuck(){return \"GNm\";})(),(function fuck(){return \"Bz\";})()," ascii

  condition:
    (uint16(0) == 0x2f0a and (all of them)
    ) or (all of them)
}