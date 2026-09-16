rule _20160921_1c739a510b202fd8658c1445b926e28b_20160921_b9d88469e8af_3475 {
  meta:
    description = "datamaliciousorder - from files 20160921_1c739a510b202fd8658c1445b926e28b.js, 20160921_b9d88469e8af8cdd67a843044d05e2bd.js, 20160921_d881ddcdbb8b37adbff592aab3771b78.js, 20160921_dd42e850834f3af27a08edf609a699b5.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "ef5e44b6b8f05f9e4eadc507955ef770936acdd360f7dcfe6bb70a36427b04b7"
    hash2       = "691dd89731d938aee086465dd311d329fb4ba2f7cee53317fdbdb84c69d5bea1"
    hash3       = "008cc7d5c2f70bbd365de36ecf9be04883f520550cbb34940b2aaf96e55207e3"
    hash4       = "d7708087ab30a8d0d937f9d460512c05c37534c0d3c387bd3e1dd7fcb84fdc58"

  strings:
    $s1 = "ion fuck(){return \"Jo\";})(),(function fuck(){return \"XCr\";})(),(function fuck(){return \"MUs\";})(),(function fuck(){return " ascii
    $s2 = "eturn \"Et\";})(),(function fuck(){return \"IOs\";})(),(function fuck(){return \"IPu\";})(),(function fuck(){return \"DRx\";})()" ascii
    $s3 = "nction fuck(){return \"AUx\";})(),(function fuck(){return \"UOe\";})(),(function fuck(){return \"IRn\";})(),(function fuck(){ret" ascii
    $s4 = ",(function fuck(){return \"IPu\";})(),(function fuck(){return \"UOe\";})(),(function fuck(){return \"YQt\";})(),(function fuck()" ascii
    $s5 = "on fuck(){return \"IPu\";})(),(function fuck(){return \"Wo0\";})(),(function fuck(){return \"Ve\";})(),(function fuck(){return " ascii
    $s6 = "ction fuck(){return \"Nm\";})(),(function fuck(){return \"QTc\";})(),(function fuck(){return \"Vb\";})(),(function fuck(){return" ascii

  condition:
    (uint16(0) == 0x2f0a and (all of them)
    ) or (all of them)
}