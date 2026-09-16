rule _20160921_63a82ecb2e4eb3b0dd878bbec885c469_20160921_abc9044816c2_1497 {
  meta:
    description = "datamaliciousorder - from files 20160921_63a82ecb2e4eb3b0dd878bbec885c469.js, 20160921_abc9044816c2455dc24ac338746b6bd5.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "0e9de62be8773f33e42da56c84c9c85d07f7c2616909543479f7803e6794a9ef"
    hash2       = "2bb53920235afb1c2d16f013bc118d1df64065eefc10c1b2b9e7a4b133850850"

  strings:
    $s1  = "eturn \"IPu\";})(),(function fuck(){return \"Zy\";})(),(function fuck(){return \"YAv\";})(),(function fuck(){return \"USf\";})()" ascii
    $s2  = "return \"Za\";})(),(function fuck(){return \"IPu\";})(),(function fuck(){return \"Nm\";})(),(function fuck(){return \"Ve\";})()," ascii
    $s3  = "tion fuck(){return \"Ve\";})(),(function fuck(){return \"Mw\";})(),(function fuck(){return \"RAi\";})(),(function fuck(){return " ascii
    $s4  = "ction fuck(){return \"IPu\";})(),(function fuck(){return \"Xw\";})(),(function fuck(){return \"Vb\";})(),(function fuck(){return" ascii
    $s5  = "uck(){return \"IPu\";})(),(function fuck(){return \"We\";})(),(function fuck(){return \"Wo0\";})(),(function fuck(){return \"IPu" ascii
    $s6  = "t\";})(),(function fuck(){return \"Ot\";})(),(function fuck(){return \"Na\";})(),(function fuck(){return \"IPu\";})(),(function " ascii
    $s7  = "\";})(),(function fuck(){return \"MBg\";})(),(function fuck(){return \"TTs\";})(),(function fuck(){return \"CCb\";})(),(function" ascii
    $s8  = "(),(function fuck(){return \"IPu\";})(),(function fuck(){return \"Zy\";})(),(function fuck(){return \"Oh\";})(),(function fuck()" ascii
    $s9  = "Za\";})(),(function fuck(){return \"IPu\";})(),(function fuck(){return \"GJx\";})(),(function fuck(){return \"Et\";})(),(functio" ascii
    $s10 = "{return \"DRx\";})(),(function fuck(){return \"IPu\";})(),(function fuck(){return \"We\";})(),(function fuck(){return \"Wo0\";})" ascii
    $s11 = "on fuck(){return \"MBg\";})(),(function fuck(){return \"Xw\";})(),(function fuck(){return \"Jo\";})(),(function fuck(){return \"" ascii
    $s12 = "ion fuck(){return \"DRx\";})(),(function fuck(){return \"IPu\";})(),(function fuck(){return \"Qh\";})(),(function fuck(){return " ascii
    $s13 = "tion fuck(){return \"IPu\";})(),(function fuck(){return \"Ug\";})(),(function fuck(){return \"Sx\";})(),(function fuck(){return " ascii

  condition:
    (uint16(0) == 0x2f0a and (8 of them)
    ) or (all of them)
}