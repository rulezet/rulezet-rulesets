rule _20160921_9c9fcc818a7064d7449eec45fbad08d9_20160921_fd5fc0674575_3099 {
  meta:
    description = "datamaliciousorder - from files 20160921_9c9fcc818a7064d7449eec45fbad08d9.js, 20160921_fd5fc067457571e92a95bd16158d41e6.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "988df854145081fce0af79178c78ce75ca8d89b6666ec2e052b7f8de43bb1101"
    hash2       = "e32ed831874bb280ae970e019573b598cf97788865b3fea13118546e435353f9"

  strings:
    $s1 = "b\";})(),(function f000(){return \"Yi\";})(),(function f000(){return \"GGn\";})(),(function f000(){return \"MDb\";})(),(function" ascii
    $s2 = "(){return \"Sj\";})(),(function f000(){return \"NBs\";})(),(function f000(){return \"GGn\";})(),(function f000(){return \"MDb\";" ascii
    $s3 = ";})(),(function f000(){return \"DNa\";})(),(function f000(){return \"MJq\";})(),(function f000(){return \"RPt\";})(),(function f" ascii
    $s4 = "ion f000(){return \"MDb\";})(),(function f000(){return \"GGn\";})(),(function f000(){return \"ZIi\";})(),(function f000(){return" ascii
    $s5 = "{return \"GGn\";})(),(function f000(){return \"Yv\";})(),(function f000(){return \"TKp\";})(),(function f000(){return \"Yi\";})(" ascii
    $s6 = "nction f000(){return \"GGn\";})(),(function f000(){return \"DYs\";})(),(function f000(){return \"Um\";})(),(function f000(){retu" ascii
    $s7 = "(){return \"DYx\";})(),(function f000(){return \"WIj\";})(),(function f000(){return \"Go\";})(),(function f000(){return \"ZIi\";" ascii

  condition:
    (uint16(0) == 0x2f0a and (all of them)
    ) or (all of them)
}