rule _20160921_85f2776f4fe640d2373f51ddbc697659_20160921_91424e3b4f10_1908 {
  meta:
    description = "datamaliciousorder - from files 20160921_85f2776f4fe640d2373f51ddbc697659.js, 20160921_91424e3b4f105c156aa0fa6f22c2306f.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "0604503e68d6aa73ca3bbdb29b958ea47ad4c81b2f77ad9db2b0e8467b1c870d"
    hash2       = "b4a035e38404ad09be99953980865cdbcda5dd05b664dff96722afb53b0c9e29"

  strings:
    $s1  = "fuck(){return \"Ot\";})(),(function fuck(){return \"YQt\";})(),(function fuck(){return \"Na\";})(),(function fuck(){return \"DRx" ascii
    $s2  = "urn \"We\";})(),(function fuck(){return \"MUs\";})(),(function fuck(){return \"Hs\";})(),(function fuck(){return \"DRx\";})(),(f" ascii
    $s3  = "fuck(){return \"We\";})(),(function fuck(){return \"MUs\";})(),(function fuck(){return \"Hs\";})(),(function fuck(){return \"IPu" ascii
    $s4  = "})(),(function fuck(){return \"DWe\";})(),(function fuck(){return \"DAa\";})(),(function fuck(){return \"Vb\";})(),(function fuc" ascii
    $s5  = "DRx\";})(),(function fuck(){return \"Qh\";})(),(function fuck(){return \"Jg\";})(),(function fuck(){return \"DRx\";})(),(functio" ascii
    $s6  = "(),(function fuck(){return \"Wo0\";})(),(function fuck(){return \"ADy\";})(),(function fuck(){return \"DRx\";})(),(function fuck" ascii
    $s7  = ",(function fuck(){return \"DWe\";})(),(function fuck(){return \"DAa\";})(),(function fuck(){return \"Vb\";})(),(function fuck(){" ascii
    $s8  = "turn \"Zy\";})(),(function fuck(){return \"Wo0\";})(),(function fuck(){return \"ADy\";})(),(function fuck(){return \"IPu\";})()," ascii
    $s9  = "turn \"DRx\";})(),(function fuck(){return \"YQt\";})(),(function fuck(){return \"Na\";})(),(function fuck(){return \"UOe\";})()," ascii
    $s10 = "unction fuck(){return \"Za\";})(),(function fuck(){return \"IPu\";})(),(function fuck(){return \"YQt\";})(),(function fuck(){ret" ascii

  condition:
    (uint16(0) == 0x2f0a and (all of them)
    ) or (all of them)
}