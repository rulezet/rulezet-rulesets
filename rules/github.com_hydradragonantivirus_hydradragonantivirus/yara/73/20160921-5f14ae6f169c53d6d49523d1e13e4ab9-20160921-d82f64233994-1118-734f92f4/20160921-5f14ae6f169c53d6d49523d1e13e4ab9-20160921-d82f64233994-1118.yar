rule _20160921_5f14ae6f169c53d6d49523d1e13e4ab9_20160921_d82f64233994_1118 {
  meta:
    description = "datamaliciousorder - from files 20160921_5f14ae6f169c53d6d49523d1e13e4ab9.js, 20160921_d82f642339947ac5ef4d322534d8cd70.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "270eb53363684986d2aef11b6b5bb4cd5c5cb316f626e41b627db2cf899b440e"
    hash2       = "1af101b4afb2b8d290446a4841d803e88cb42849fb95f0cea056677487805eb6"

  strings:
    $s1  = "k(){return \"Za\";})(),(function fuck(){return \"IPu\";})(),(function fuck(){return \"Ai\";})(),(function fuck(){return \"Nm\";}" ascii
    $s2  = "Pu\";})(),(function fuck(){return \"Xw\";})(),(function fuck(){return \"Fv\";})(),(function fuck(){return \"Xw\";})(),(function " ascii
    $s3  = "ck(){return \"IPu\";})(),(function fuck(){return \"ZWu\";})(),(function fuck(){return \"Hs\";})(),(function fuck(){return \"Ik\"" ascii
    $s4  = "(function fuck(){return \"Xg\";})(),(function fuck(){return \"FJs\";})(),(function fuck(){return \"Xw\";})(),(function fuck(){re" ascii
    $s5  = "rn \"Wo0\";})(),(function fuck(){return \"GWo\";})(),(function fuck(){return \"IPu\";})(),(function fuck(){return \"MBg\";})(),(" ascii
    $s6  = "(){return \"Za\";})(),(function fuck(){return \"IPu\";})(),(function fuck(){return \"ZLd\";})(),(function fuck(){return \"EHo\";" ascii
    $s7  = ";})(),(function fuck(){return \"Vb\";})(),(function fuck(){return \"AUx\";})(),(function fuck(){return \"NKq\";})(),(function fu" ascii
    $s8  = "uck(){return \"MBg\";})(),(function fuck(){return \"IPu\";})(),(function fuck(){return \"Xw\";})(),(function fuck(){return \"SUi" ascii
    $s9  = "urn \"IPu\";})(),(function fuck(){return \"Xw\";})(),(function fuck(){return \"FJs\";})(),(function fuck(){return \"Za\";})(),(f" ascii
    $s10 = "ion fuck(){return \"Xg\";})(),(function fuck(){return \"YAv\";})(),(function fuck(){return \"YAv\";})(),(function fuck(){return " ascii
    $s11 = " \"ZWu\";})(),(function fuck(){return \"EHo\";})(),(function fuck(){return \"IPu\";})(),(function fuck(){return \"MBg\";})(),(fu" ascii
    $s12 = "k(){return \"Xw\";})(),(function fuck(){return \"Pc\";})(),(function fuck(){return \"XHj\";})(),(function fuck(){return \"QTc\";" ascii
    $s13 = "n \"Vb\";})(),(function fuck(){return \"GNm\";})(),(function fuck(){return \"IPu\";})(),(function fuck(){return \"DRx\";})(),(fu" ascii
    $s14 = "n fuck(){return \"Za\";})(),(function fuck(){return \"IPu\";})(),(function fuck(){return \"GJx\";})(),(function fuck(){return \"" ascii
    $s15 = "{return \"Xg\";})(),(function fuck(){return \"Ik\";})(),(function fuck(){return \"Fv\";})(),(function fuck(){return \"Xg\";})()," ascii
    $s16 = "ion fuck(){return \"IPu\";})(),(function fuck(){return \"Et\";})(),(function fuck(){return \"Xg\";})(),(function fuck(){return " ascii
    $s17 = "return \"RAi\";})(),(function fuck(){return \"TTs\";})(),(function fuck(){return \"LGo\";})(),(function fuck(){return \"YQt\";})" ascii

  condition:
    (uint16(0) == 0x2f0a and (8 of them)
    ) or (all of them)
}