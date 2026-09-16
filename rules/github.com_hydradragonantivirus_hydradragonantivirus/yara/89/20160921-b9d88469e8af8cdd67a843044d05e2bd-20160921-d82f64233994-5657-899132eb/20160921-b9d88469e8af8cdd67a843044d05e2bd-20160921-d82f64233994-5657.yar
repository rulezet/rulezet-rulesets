rule _20160921_b9d88469e8af8cdd67a843044d05e2bd_20160921_d82f64233994_5657 {
  meta:
    description = "datamaliciousorder - from files 20160921_b9d88469e8af8cdd67a843044d05e2bd.js, 20160921_d82f642339947ac5ef4d322534d8cd70.js, 20160921_d881ddcdbb8b37adbff592aab3771b78.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "691dd89731d938aee086465dd311d329fb4ba2f7cee53317fdbdb84c69d5bea1"
    hash2       = "1af101b4afb2b8d290446a4841d803e88cb42849fb95f0cea056677487805eb6"
    hash3       = "008cc7d5c2f70bbd365de36ecf9be04883f520550cbb34940b2aaf96e55207e3"

  strings:
    $s1 = "ction fuck(){return \"OQr\";})(),(function fuck(){return \"GJx\";})(),(function fuck(){return \"Et\";})(),(function fuck(){retur" ascii
    $s2 = "(function fuck(){return \"USf\";})(),(function fuck(){return \"TTs\";})(),(function fuck(){return \"Et\";})(),(function fuck(){r" ascii
    $s3 = " fuck(){return \"YQt\";})(),(function fuck(){return \"UOe\";})(),(function fuck(){return \"IRn\";})(),(function fuck(){return \"" ascii
    $s4 = "uck(){return \"Wo0\";})(),(function fuck(){return \"Ve\";})(),(function fuck(){return \"Na\";})(),(function fuck(){return \"USf" ascii
    $s5 = "fuck(){return \"RAi\";})(),(function fuck(){return \"IRn\";})(),(function fuck(){return \"MBg\";})(),(function fuck(){return \"A" ascii

  condition:
    (uint16(0) == 0x2f0a and (all of them)
    ) or (all of them)
}