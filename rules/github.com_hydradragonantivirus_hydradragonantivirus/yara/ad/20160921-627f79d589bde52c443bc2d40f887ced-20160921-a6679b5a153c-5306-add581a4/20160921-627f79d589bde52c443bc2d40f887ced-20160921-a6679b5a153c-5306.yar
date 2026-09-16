rule _20160921_627f79d589bde52c443bc2d40f887ced_20160921_a6679b5a153c_5306 {
  meta:
    description = "datamaliciousorder - from files 20160921_627f79d589bde52c443bc2d40f887ced.js, 20160921_a6679b5a153c4bb3f7cb9fe7c02dc710.js, 20160921_c779962dc8b38bbb280b695e631131fa.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "f23a9d984b71a422ca30ec7f94f4a4cb0a2303699dc80edbced4a4c608e370e4"
    hash2       = "c54f97191e0c15791315cc1823b0fbce23679bebe5b1ce5c2b6b4895074c1121"
    hash3       = "cf3f9e3180d8fa16719dbea90d762850a1742512c7be6bc42325dc9e094add30"

  strings:
    $s1 = "turn \"IPu\";})(),(function fuck(){return \"GJx\";})(),(function fuck(){return \"UXf\";})(),(function fuck(){return \"DRx\";})()" ascii
    $s2 = "unction fuck(){return \"AUx\";})(),(function fuck(){return \"Py\";})(),(function fuck(){return \"MBg\";})(),(function fuck(){ret" ascii
    $s3 = "rn \"CTm\";})(),(function fuck(){return \"Ai\";})(),(function fuck(){return \"Cd\";})(),(function fuck(){return \"MUs\";})(),(fu" ascii
    $s4 = "function fuck(){return \"Py\";})(),(function fuck(){return \"DRx\";})(),(function fuck(){return \"Et\";})(),(function fuck(){ret" ascii
    $s5 = "(),(function fuck(){return \"Py\";})(),(function fuck(){return \"Py\";})(),(function fuck(){return \"NKq\";})(),(function fuck()" ascii

  condition:
    (uint16(0) == 0x2f0a and (all of them)
    ) or (all of them)
}