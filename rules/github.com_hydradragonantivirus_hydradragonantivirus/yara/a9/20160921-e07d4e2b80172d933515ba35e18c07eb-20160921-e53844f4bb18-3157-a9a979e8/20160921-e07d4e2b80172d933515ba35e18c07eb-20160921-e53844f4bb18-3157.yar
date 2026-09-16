rule _20160921_e07d4e2b80172d933515ba35e18c07eb_20160921_e53844f4bb18_3157 {
  meta:
    description = "datamaliciousorder - from files 20160921_e07d4e2b80172d933515ba35e18c07eb.js, 20160921_e53844f4bb18305322896332fbd017e8.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "d93efcba4ba3ef570f21adda2cc5413ab9ed3865a53a97ad1e05113ebc7c4787"
    hash2       = "b8484bab412a47fffb0a694f32ca5de3480841bd1c0806d0a7e6e86dfd21de6c"

  strings:
    $s1 = "uck(){return \"DWe\";})(),(function fuck(){return \"Sx\";})(),(function fuck(){return \"UOe\";})(),(function fuck(){return \"DRx" ascii
    $s2 = "})(),(function fuck(){return \"Yk\";})(),(function fuck(){return \"MUs\";})(),(function fuck(){return \"Jo\";})(),(function fuck" ascii
    $s3 = " fuck(){return \"MUs\";})(),(function fuck(){return \"Py\";})(),(function fuck(){return \"IRn\";})(),(function fuck(){return \"O" ascii
    $s4 = "eturn \"Ve\";})(),(function fuck(){return \"Av\";})(),(function fuck(){return \"Np\";})(),(function fuck(){return \"IRn\";})(),(" ascii
    $s5 = "),(function fuck(){return \"Ot\";})(),(function fuck(){return \"AUx\";})(),(function fuck(){return \"DRx\";})(),(function fuck()" ascii
    $s6 = "n \"ZWu\";})(),(function fuck(){return \"Cd\";})(),(function fuck(){return \"AUx\";})(),(function fuck(){return \"DRx\";})(),(fu" ascii
    $s7 = "unction fuck(){return \"IPu\";})(),(function fuck(){return \"Et\";})(),(function fuck(){return \"Cd\";})(),(function fuck(){retu" ascii

  condition:
    (uint16(0) == 0x2f0a and (all of them)
    ) or (all of them)
}