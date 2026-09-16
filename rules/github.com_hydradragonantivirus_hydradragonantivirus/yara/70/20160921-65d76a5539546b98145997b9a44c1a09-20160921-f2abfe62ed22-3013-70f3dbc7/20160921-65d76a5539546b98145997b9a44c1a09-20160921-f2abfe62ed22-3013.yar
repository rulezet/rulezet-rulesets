rule _20160921_65d76a5539546b98145997b9a44c1a09_20160921_f2abfe62ed22_3013 {
  meta:
    description = "datamaliciousorder - from files 20160921_65d76a5539546b98145997b9a44c1a09.js, 20160921_f2abfe62ed227fb547869419a6d3af3c.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "0a1b81d7435f521382a4cec07d80cbc8fe75f2ebac92fb6c4d105b19ec098560"
    hash2       = "843cfa29e93bfa9adfe4410735aacbf939d01a404dc3c507c0562f478b65086f"

  strings:
    $s1 = "uck(){return \"Oh\";})(),(function fuck(){return \"Ai\";})(),(function fuck(){return \"Xg\";})(),(function fuck(){return \"TTs\"" ascii
    $s2 = "),(function fuck(){return \"PDf\";})(),(function fuck(){return \"Pc\";})(),(function fuck(){return \"ZWu\";})(),(function fuck()" ascii
    $s3 = "on fuck(){return \"IPu\";})(),(function fuck(){return \"Vf\";})(),(function fuck(){return \"Ai\";})(),(function fuck(){return \"" ascii
    $s4 = ";})(),(function fuck(){return \"Ai\";})(),(function fuck(){return \"Xg\";})(),(function fuck(){return \"IPu\";})(),(function fuc" ascii
    $s5 = "{return \"IPu\";})(),(function fuck(){return \"Cd\";})(),(function fuck(){return \"Ve\";})(),(function fuck(){return \"MUs\";})(" ascii
    $s6 = "k(){return \"XHj\";})(),(function fuck(){return \"Fv\";})(),(function fuck(){return \"OQr\";})(),(function fuck(){return \"Py\";" ascii
    $s7 = "ction fuck(){return \"Za\";})(),(function fuck(){return \"IPu\";})(),(function fuck(){return \"Oh\";})(),(function fuck(){return" ascii

  condition:
    (uint16(0) == 0x2f0a and (all of them)
    ) or (all of them)
}