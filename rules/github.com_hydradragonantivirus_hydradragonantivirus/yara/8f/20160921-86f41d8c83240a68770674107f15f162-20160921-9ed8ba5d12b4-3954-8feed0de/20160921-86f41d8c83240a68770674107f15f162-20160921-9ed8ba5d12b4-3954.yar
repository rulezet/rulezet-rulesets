rule _20160921_86f41d8c83240a68770674107f15f162_20160921_9ed8ba5d12b4_3954 {
  meta:
    description = "datamaliciousorder - from files 20160921_86f41d8c83240a68770674107f15f162.js, 20160921_9ed8ba5d12b4be06b54bbeb7c9325180.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "56a4c0b8742284d9e8907df1b8d73d9c73ee82bc9595e88d869c555afd77312d"
    hash2       = "19b8471b5bf67286e6bfe340e23abef1def848daa18c886f2eddc2eeaa160df7"

  strings:
    $s1 = "n \"GGn\";})(),(function f000(){return \"Vu\";})(),(function f000(){return \"Sq\";})(),(function f000(){return \"GGn\";})(),(fun" ascii
    $s2 = "{return \"BQb\";})(),(function f000(){return \"Oe\";})(),(function f000(){return \"QDg\";})(),(function f000(){return \"DNa\";})" ascii
    $s3 = "Oe\";})(),(function f000(){return \"Wy\";})(),(function f000(){return \"PTs\";})(),(function f000(){return \"Iq\";})(),(function" ascii
    $s4 = "tion f000(){return \"Vj\";})(),(function f000(){return \"Nx\";})(),(function f000(){return \"DIa\";})(),(function f000(){return " ascii
    $s5 = "return \"DYx\";})(),(function f000(){return \"Tn\";})(),(function f000(){return \"Wy\";})(),(function f000(){return \"ZGq\";})()" ascii
    $s6 = "function f000(){return \"DYx\";})(),(function f000(){return \"Ml\";})(),(function f000(){return \"DNa\";})(),(function f000(){re" ascii

  condition:
    (uint16(0) == 0x2f0a and (all of them)
    ) or (all of them)
}