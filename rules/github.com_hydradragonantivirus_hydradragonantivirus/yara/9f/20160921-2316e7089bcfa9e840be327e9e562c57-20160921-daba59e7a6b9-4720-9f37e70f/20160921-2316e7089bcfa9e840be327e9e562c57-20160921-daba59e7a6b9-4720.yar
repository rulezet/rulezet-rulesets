rule _20160921_2316e7089bcfa9e840be327e9e562c57_20160921_daba59e7a6b9_4720 {
  meta:
    description = "datamaliciousorder - from files 20160921_2316e7089bcfa9e840be327e9e562c57.js, 20160921_daba59e7a6b9ed6983cd2cbef1eb1597.js, 20160921_f232e0ba2dbd66b232f717e912f70cd7.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "11216ce48a9d383f0d3cab03de05ba1550ae25c7b5d18a758666cfdd75159fe2"
    hash2       = "94c619539e853fdec1958270da7516c52bbcf442ee9ca0569d11e19e70ae29eb"
    hash3       = "d8231c7ebf650f58f63f7ed6d3017e0ee9895c1dd821750dcc6c78003fc81b2b"

  strings:
    $s1 = "(){return \"RLk\";})(),(function f000(){return \"YTp\";})(),(function f000(){return \"DNa\";})(),(function f000(){return \"GGn\"" ascii
    $s2 = "Yh\";})(),(function f000(){return \"PTs\";})(),(function f000(){return \"DIa\";})(),(function f000(){return \"Zj\";})(),(functio" ascii
    $s3 = "{return \"Vu\";})(),(function f000(){return \"Iq\";})(),(function f000(){return \"PTs\";})(),(function f000(){return \"Ml\";})()" ascii
    $s4 = "unction f000(){return \"DAp\";})(),(function f000(){return \"SGs\";})(),(function f000(){return \"Qz\";})(),(function f000(){ret" ascii
    $s5 = ";})(),(function f000(){return \"DNa\";})(),(function f000(){return \"DNa\";})(),(function f000(){return \"TRc\";})(),(function f" ascii

  condition:
    (uint16(0) == 0x2f0a and (all of them)
    ) or (all of them)
}