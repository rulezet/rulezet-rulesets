rule _20160921_b9d88469e8af8cdd67a843044d05e2bd_20160921_c0cd20cf50e8_4036 {
  meta:
    description = "datamaliciousorder - from files 20160921_b9d88469e8af8cdd67a843044d05e2bd.js, 20160921_c0cd20cf50e8d47fdd1303227435227a.js, 20160921_d881ddcdbb8b37adbff592aab3771b78.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "691dd89731d938aee086465dd311d329fb4ba2f7cee53317fdbdb84c69d5bea1"
    hash2       = "3d34400bc3cfc9235dbf1a201a7f50b72821566d70727533493e74fbeb8a5514"
    hash3       = "008cc7d5c2f70bbd365de36ecf9be04883f520550cbb34940b2aaf96e55207e3"

  strings:
    $s1 = "urn \"IOs\";})(),(function fuck(){return \"Fv\";})(),(function fuck(){return \"TTs\";})(),(function fuck(){return \"Wo\";})(),(f" ascii
    $s2 = "rn \"Ot\";})(),(function fuck(){return \"Py\";})(),(function fuck(){return \"GNm\";})(),(function fuck(){return \"NKq\";})(),(fu" ascii
    $s3 = "\"AUx\";})(),(function fuck(){return \"RAi\";})(),(function fuck(){return \"Np\";})(),(function fuck(){return \"ADy\";})(),(func" ascii
    $s4 = "urn \"OPz\";})(),(function fuck(){return \"IPu\";})(),(function fuck(){return \"We\";})(),(function fuck(){return \"IOs\";})(),(" ascii
    $s5 = "\"TTs\";})(),(function fuck(){return \"Vb\";})(),(function fuck(){return \"AUx\";})(),(function fuck(){return \"Np\";})(),(funct" ascii
    $s6 = "\"DRx\";})(),(function fuck(){return \"IPu\";})(),(function fuck(){return \"Yk\";})(),(function fuck(){return \"Ik\";})(),(funct" ascii

  condition:
    (uint16(0) == 0x2f0a and (all of them)
    ) or (all of them)
}