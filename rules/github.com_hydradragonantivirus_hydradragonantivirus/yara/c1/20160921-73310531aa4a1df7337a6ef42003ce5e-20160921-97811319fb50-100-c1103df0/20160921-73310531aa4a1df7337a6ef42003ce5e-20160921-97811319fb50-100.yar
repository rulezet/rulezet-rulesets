rule _20160921_73310531aa4a1df7337a6ef42003ce5e_20160921_97811319fb50_100 {
  meta:
    description = "datamaliciousorder - from files 20160921_73310531aa4a1df7337a6ef42003ce5e.js, 20160921_97811319fb50bbd834b521ddcbb35712.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "c1f6942ac4bb494bebef47181bbb9c9fe04d3d155e4bc18b2ff21e74c6592f78"
    hash2       = "4105b34a1f3797b1fc5f9b5d7f49d995c2796d5876f07b87b344f6c7e8c0625e"

  strings:
    $s1  = ")(),(function fuck(){return \"KVh\";})(),(function fuck(){return \"ADy\";})(),(function fuck(){return \"DRx\";})(),(function fuc" ascii
    $s2  = "rn \"Vb\";})(),(function fuck(){return \"DRx\";})(),(function fuck(){return \"YQt\";})(),(function fuck(){return \"Na\";})(),(fu" ascii
    $s3  = "{return \"Ai\";})(),(function fuck(){return \"Jh\";})(),(function fuck(){return \"Vb\";})(),(function fuck(){return \"IPu\";})()" ascii
    $s4  = "tion fuck(){return \"ADy\";})(),(function fuck(){return \"TTs\";})(),(function fuck(){return \"Et\";})(),(function fuck(){return" ascii
    $s5  = "ction fuck(){return \"XCr\";})(),(function fuck(){return \"SUi\";})(),(function fuck(){return \"DRx\";})(),(function fuck(){retu" ascii
    $s6  = "fuck(){return \"Vb\";})(),(function fuck(){return \"Hs\";})(),(function fuck(){return \"IPu\";})(),(function fuck(){return \"IKv" ascii
    $s7  = "tion fuck(){return \"IKv\";})(),(function fuck(){return \"IPu\";})(),(function fuck(){return \"Hs\";})(),(function fuck(){return" ascii
    $s8  = "urn \"DRx\";})(),(function fuck(){return \"Yk\";})(),(function fuck(){return \"XHj\";})(),(function fuck(){return \"FJs\";})(),(" ascii
    $s9  = "nction fuck(){return \"UXf\";})(),(function fuck(){return \"DAa\";})(),(function fuck(){return \"TTs\";})(),(function fuck(){ret" ascii
    $s10 = ")(),(function fuck(){return \"Cd\";})(),(function fuck(){return \"Jh\";})(),(function fuck(){return \"IPu\";})(),(function fuck(" ascii
    $s11 = "ck(){return \"DRx\";})(),(function fuck(){return \"ZWu\";})(),(function fuck(){return \"KVh\";})(),(function fuck(){return \"DRx" ascii
    $s12 = "n \"IPu\";})(),(function fuck(){return \"Yk\";})(),(function fuck(){return \"Ve\";})(),(function fuck(){return \"Na\";})(),(func" ascii
    $s13 = "k(){return \"DWe\";})(),(function fuck(){return \"Dc\";})(),(function fuck(){return \"LGo\";})(),(function fuck(){return \"TTs\"" ascii
    $s14 = "ck(){return \"Yk\";})(),(function fuck(){return \"FJs\";})(),(function fuck(){return \"NKq\";})(),(function fuck(){return \"GNm" ascii
    $s15 = "(){return \"Hs\";})(),(function fuck(){return \"Jo\";})(),(function fuck(){return \"IPu\";})(),(function fuck(){return \"DRx\";}" ascii
    $s16 = ";})(),(function fuck(){return \"IPu\";})(),(function fuck(){return \"DWe\";})(),(function fuck(){return \"Dc\";})(),(function fu" ascii
    $s17 = "{return \"MIl\";})(),(function fuck(){return \"Et\";})(),(function fuck(){return \"Ik\";})(),(function fuck(){return \"USf\";})(" ascii
    $s18 = "function fuck(){return \"IPu\";})(),(function fuck(){return \"MIl\";})(),(function fuck(){return \"FJs\";})(),(function fuck(){r" ascii
    $s19 = "k\";})(),(function fuck(){return \"Oh\";})(),(function fuck(){return \"KVh\";})(),(function fuck(){return \"IPu\";})(),(function" ascii
    $s20 = "turn \"Za\";})(),(function fuck(){return \"DRx\";})(),(function fuck(){return \"Yk\";})(),(function fuck(){return \"Ar\";})(),(f" ascii

  condition:
    (uint16(0) == 0x2f0a and (8 of them)
    ) or (all of them)
}