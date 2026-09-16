rule _20160921_65d76a5539546b98145997b9a44c1a09_20160921_70b567ca258b_3014 {
  meta:
    description = "datamaliciousorder - from files 20160921_65d76a5539546b98145997b9a44c1a09.js, 20160921_70b567ca258b3c505e14f3c712366f09.js, 20160921_70d636d209e6f109a21746567376cc81.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "0a1b81d7435f521382a4cec07d80cbc8fe75f2ebac92fb6c4d105b19ec098560"
    hash2       = "8cf06551c554a2db81fe1bf37b069b40e558f931913e7d2572bdd18b36f57c73"
    hash3       = "6e26044e7a07a5a675f3b388e6309b138b9e7a1aa61556485f444025164a158e"

  strings:
    $s1 = ";})(),(function fuck(){return \"DWe\";})(),(function fuck(){return \"Ik\";})(),(function fuck(){return \"Np\";})(),(function fuc" ascii
    $s2 = ",(function fuck(){return \"DRx\";})(),(function fuck(){return \"XHj\";})(),(function fuck(){return \"GJx\";})(),(function fuck()" ascii
    $s3 = " \"Ot\";})(),(function fuck(){return \"XCr\";})(),(function fuck(){return \"MUs\";})(),(function fuck(){return \"MOj\";})(),(fun" ascii
    $s4 = "on fuck(){return \"IPu\";})(),(function fuck(){return \"CCb\";})(),(function fuck(){return \"Fv\";})(),(function fuck(){return " ascii
    $s5 = "uck(){return \"IPu\";})(),(function fuck(){return \"Qh\";})(),(function fuck(){return \"SUi\";})(),(function fuck(){return \"LGo" ascii
    $s6 = "turn \"Zy\";})(),(function fuck(){return \"XHj\";})(),(function fuck(){return \"GWo\";})(),(function fuck(){return \"IRn\";})()," ascii
    $s7 = "n \"ZVi\";})(),(function fuck(){return \"Jo\";})(),(function fuck(){return \"IPu\";})(),(function fuck(){return \"DRx\";})(),(fu" ascii

  condition:
    (uint16(0) == 0x2f0a and (all of them)
    ) or (all of them)
}