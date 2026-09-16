rule _20160921_9ef73b9f4f78d9ac2f908b3cdd8db13d_20160921_b9d88469e8af_5601 {
  meta:
    description = "datamaliciousorder - from files 20160921_9ef73b9f4f78d9ac2f908b3cdd8db13d.js, 20160921_b9d88469e8af8cdd67a843044d05e2bd.js, 20160921_d881ddcdbb8b37adbff592aab3771b78.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "31bd1528e102f576486e80b1ead7224fc04db7a81b4fbf1ae11c4416b5e4bd57"
    hash2       = "691dd89731d938aee086465dd311d329fb4ba2f7cee53317fdbdb84c69d5bea1"
    hash3       = "008cc7d5c2f70bbd365de36ecf9be04883f520550cbb34940b2aaf96e55207e3"

  strings:
    $s1 = "turn \"LGo\";})(),(function fuck(){return \"RAi\";})(),(function fuck(){return \"Vb\";})(),(function fuck(){return \"GNm\";})()," ascii
    $s2 = "return \"GNm\";})(),(function fuck(){return \"ADy\";})(),(function fuck(){return \"NKq\";})(),(function fuck(){return \"Ug\";})(" ascii
    $s3 = "unction fuck(){return \"CTm\";})(),(function fuck(){return \"Ar\";})(),(function fuck(){return \"TTs\";})(),(function fuck(){ret" ascii
    $s4 = "l\";})(),(function fuck(){return \"To\";})(),(function fuck(){return \"Py\";})(),(function fuck(){return \"IPu\";})(),(function " ascii
    $s5 = "urn \"IPu\";})(),(function fuck(){return \"Ar\";})(),(function fuck(){return \"MOj\";})(),(function fuck(){return \"Ug\";})(),(f" ascii

  condition:
    (uint16(0) == 0x2f0a and (all of them)
    ) or (all of them)
}